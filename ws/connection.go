package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/inference-sh/goutils/pubsub"
)

const (
	// Key prefixes for Redis
	connectionPrefix = "ws:connection:"
	// TTL for connection registrations
	connectionTTL = 5 * time.Minute
)

type ConnectionStore interface {
	Register(id, instanceID string) error
	Unregister(id string) error
	Refresh(id string) error
	Find(id string) (*string, error)
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
	key := connectionPrefix + id
	err := r.client.Set(context.Background(), key, instanceID, connectionTTL).Err()
	return err
}

func (r *RedisConnectionStore) Unregister(id string) error {
	key := connectionPrefix + id
	err := r.client.Del(context.Background(), key).Err()
	return err
}

func (r *RedisConnectionStore) Refresh(id string) error {
	key := connectionPrefix + id
	return r.client.Expire(context.Background(), key, connectionTTL).Err()
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
