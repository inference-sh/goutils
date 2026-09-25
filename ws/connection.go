package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/inference-sh/goutils/pubsub"
	"github.com/redis/go-redis/v9"
)

const (
	// Key prefixes for Redis
	connectionPrefix = "ws:connection:"
	// connectionTTL is a connection lease's lifetime. The holding instance
	// renews it every connectionRefreshEvery, so a lease outlives its holder
	// by at most this long: an instance that crashed without closing its
	// sockets has its connections read as gone within connectionTTL.
	connectionTTL = 45 * time.Second
	// connectionRefreshEvery is how often a holder renews its leases; a
	// third of the TTL, so two renewals can be missed before one lapses.
	connectionRefreshEvery = 15 * time.Second
)

// ConnectionStore is the cross-instance registry of which instance holds each
// connection. Each entry is a lease owned by one instance: whoever connected
// last owns it, and only the owner may renew or release it, so an instance
// that lost a connection to another cannot erase the new holder's entry.
type ConnectionStore interface {
	// Register takes the lease for id on behalf of instanceID. A newer
	// connection always wins, replacing any previous holder.
	Register(id, instanceID string) error
	// Unregister releases the lease only if instanceID still holds it, and
	// reports whether it did. False means the connection moved to another
	// instance (or the lease had lapsed): the caller no longer speaks for it.
	Unregister(id, instanceID string) (bool, error)
	// Refresh renews each lease in ids that instanceID holds, reclaims any that
	// lapsed while the connection is still open here, and returns the ids
	// another instance holds, which it leaves alone. One round trip per batch.
	Refresh(ids []string, instanceID string) (heldElsewhere []string, err error)
	// Find returns the instance holding id, or nil when no one does.
	Find(id string) (*string, error)
	// Live returns, for the ids that have a holder, which instance holds each,
	// in one round trip. Absent ids are not connected anywhere.
	Live(ids []string) (map[string]string, error)
	SendToInstance(instanceID, connectionID, msgType string, data []byte) error

	Subscribe(channel string, callback func(message []byte)) error
	Unsubscribe(channel string) error
	Publish(channel string, message []byte) error
}

type RedisConnectionStore struct {
	client *redis.Client
	pubsub pubsub.PubSub
}

func NewRedisConnectionStore(client *redis.Client) *RedisConnectionStore {
	return &RedisConnectionStore{
		client: client,
		pubsub: pubsub.NewRedisPubSub(client),
	}
}
func (r *RedisConnectionStore) Register(id string, instanceID string) error {
	return r.client.Set(context.Background(), connectionPrefix+id, instanceID, connectionTTL).Err()
}

// releaseScript deletes a lease only while it still names the caller.
var releaseScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("DEL", KEYS[1])
end
return 0`)

func (r *RedisConnectionStore) Unregister(id string, instanceID string) (bool, error) {
	n, err := releaseScript.Run(context.Background(), r.client, []string{connectionPrefix + id}, instanceID).Int()
	return n == 1, err
}

// refreshScript renews each of the caller's leases, reclaims lapsed ones, and
// leaves another instance's alone, returning 1 or 0 per key in order.
var refreshScript = redis.NewScript(`
local held = {}
for i, key in ipairs(KEYS) do
	local holder = redis.call("GET", key)
	if holder == false then
		redis.call("SET", key, ARGV[1], "PX", ARGV[2])
		held[i] = 1
	elseif holder == ARGV[1] then
		redis.call("PEXPIRE", key, ARGV[2])
		held[i] = 1
	else
		held[i] = 0
	end
end
return held`)

// refreshBatch bounds how many leases one refresh script touches.
const refreshBatch = 500

func (r *RedisConnectionStore) Refresh(ids []string, instanceID string) ([]string, error) {
	var heldElsewhere []string
	for start := 0; start < len(ids); start += refreshBatch {
		batch := ids[start:min(start+refreshBatch, len(ids))]
		keys := make([]string, len(batch))
		for i, id := range batch {
			keys[i] = connectionPrefix + id
		}
		held, err := refreshScript.Run(context.Background(), r.client, keys, instanceID, connectionTTL.Milliseconds()).Int64Slice()
		if err != nil {
			return heldElsewhere, err
		}
		for i, h := range held {
			if h == 0 {
				heldElsewhere = append(heldElsewhere, batch[i])
			}
		}
	}
	return heldElsewhere, nil
}

func (r *RedisConnectionStore) Live(ids []string) (map[string]string, error) {
	live := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return live, nil
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = connectionPrefix + id
	}
	vals, err := r.client.MGet(context.Background(), keys...).Result()
	if err != nil {
		return nil, err
	}
	for i, v := range vals {
		if holder, ok := v.(string); ok {
			live[ids[i]] = holder
		}
	}
	return live, nil
}

// FindConnection looks up which instance has a given connection
func (r *RedisConnectionStore) Find(id string) (*string, error) {
	key := connectionPrefix + id
	instanceID, err := r.client.Get(context.Background(), key).Result()
	if err == redis.Nil {
		return nil, nil // Connection not found
	}
	if err != nil {
		return nil, err
	}
	return &instanceID, nil
}

// RequestMessage sends a message to a specific instance for delivery to a connection
func (r *RedisConnectionStore) SendToInstance(targetInstanceID string, connectionID string, msgType string, data []byte) error {
	msg := struct {
		ConnectionID string          `json:"connection_id"`
		Type         string          `json:"type"`
		Data         json.RawMessage `json:"data"`
	}{
		ConnectionID: connectionID,
		Type:         msgType,
		Data:         data,
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	return r.client.Publish(context.Background(), fmt.Sprintf("instance_%s", targetInstanceID), msgBytes).Err()
}

func (r *RedisConnectionStore) Subscribe(channel string, callback func(message []byte)) error {
	return r.pubsub.Subscribe(channel, callback)
}

func (r *RedisConnectionStore) Unsubscribe(channel string) error {
	return r.pubsub.Unsubscribe(channel)
}

func (r *RedisConnectionStore) Publish(channel string, message []byte) error {
	return r.pubsub.Publish(channel, message)
}
