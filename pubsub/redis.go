package pubsub

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/inference-sh/goutils/logging"
	"github.com/redis/go-redis/v9"
)

// heartbeat is how often the subscription pings Redis. A connection that has
// answered nothing, not even a ping, for two heartbeats is dead: a half-open
// TCP connection would otherwise block the reader forever and lose every
// message silently.
const heartbeat = 15 * time.Second

// retryBackoff paces reads while Redis is unreachable.
const retryBackoff = 100 * time.Millisecond

// RedisPubSub implements the ws.PubSub interface using Redis.
//
// Redis pub/sub delivers at most once: a message published while the
// subscription's connection is down is gone. go-redis reconnects and
// resubscribes on its own, so the loss is invisible unless the reader looks
// for it. This one reads the subscription directly and reports every
// interruption through OnGap once delivery has resumed, so subscribers can
// reconcile what they may have missed.
type RedisPubSub struct {
	client    *redis.Client
	pubsub    *redis.PubSub
	mu        sync.RWMutex
	callbacks map[string]func(message []byte)
	stopCh    chan struct{} // Closed to signal intentional shutdown

	gapMu sync.RWMutex
	gaps  []func()
}

func NewRedisPubSub(client *redis.Client) *RedisPubSub {
	return &RedisPubSub{
		client:    client,
		callbacks: make(map[string]func(message []byte)),
	}
}

func NewRedisClient(redisURL string) (*redis.Client, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opt)

	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return client, nil
}

func NewRedisPubSubWithURL(redisURL string) (*RedisPubSub, error) {
	client, err := NewRedisClient(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis client: %w", err)
	}

	return NewRedisPubSub(client), nil
}

// OnGap registers fn to run after every interruption during which messages
// may have been lost, once the subscription delivers again. See GapReporter.
func (r *RedisPubSub) OnGap(fn func()) {
	r.gapMu.Lock()
	defer r.gapMu.Unlock()
	r.gaps = append(r.gaps, fn)
}

func (r *RedisPubSub) gap() {
	r.gapMu.RLock()
	fns := append([]func(){}, r.gaps...)
	r.gapMu.RUnlock()
	for _, fn := range fns {
		fn()
	}
}

func (r *RedisPubSub) Publish(channel string, message []byte) error {
	return r.client.Publish(context.Background(), channel, message).Err()
}

func (r *RedisPubSub) Subscribe(channel string, callback func(message []byte)) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.callbacks[channel] = callback

	if r.pubsub == nil {
		r.pubsub = r.client.Subscribe(context.Background())
		r.stopCh = make(chan struct{})
		go r.listen(r.pubsub, r.stopCh, false)
	}

	if err := r.pubsub.Subscribe(context.Background(), channel); err != nil {
		delete(r.callbacks, channel)
		return fmt.Errorf("failed to subscribe to channel: %w", err)
	}

	return nil
}

// listen reads one subscription until it is shut down or found dead. Any
// failed read may have lost messages: go-redis reconnects and resubscribes on
// the next read, and the first read that succeeds after it reports the gap.
// That read is at the earliest the pong of a ping sent after resubscribing,
// so Redis is delivering again before anyone reconciles. lost starts a listener that
// replaces a dead one.
func (r *RedisPubSub) listen(ps *redis.PubSub, stopCh chan struct{}, lost bool) {
	go r.ping(ps, stopCh)
	if lost {
		// Its pong is the first read, and it proves the replacement is live.
		_ = ps.Ping(context.Background())
	}

	for {
		msg, err := ps.ReceiveTimeout(context.Background(), 2*heartbeat)
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
			}
			if errors.Is(err, redis.ErrClosed) {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Not even a pong in two heartbeats: the connection is dead
				// but go-redis does not treat a timeout as one. Replace it.
				logging.Info("pubsub").Msgf("Redis PubSub silent for %s, reconnecting", 2*heartbeat)
				r.reopen(stopCh)
				return
			}
			if !lost {
				logging.Info("pubsub").Msgf("Redis PubSub read failed, messages may be lost until it resubscribes: %v", err)
			}
			lost = true
			// Back off while Redis is unreachable rather than spin.
			select {
			case <-stopCh:
				return
			case <-time.After(retryBackoff):
			}
			// The ping reconnects and resubscribes, and its pong follows the
			// subscription on the same connection: the next read that succeeds
			// proves delivery is back. The subscription's own confirmation
			// is consumed inside go-redis and never reaches Receive.
			_ = ps.Ping(context.Background())
			continue
		}
		if lost {
			lost = false
			logging.Info("pubsub").Msgf("Redis PubSub delivering again after a gap")
			r.gap()
		}

		m, ok := msg.(*redis.Message)
		if !ok {
			// Subscription confirmations and pongs.
			continue
		}
		r.mu.RLock()
		callback, exists := r.callbacks[m.Channel]
		r.mu.RUnlock()
		if exists {
			callback([]byte(m.Payload))
		}
	}
}

// ping keeps traffic on the subscription so listen can tell a quiet channel
// from a dead connection.
func (r *RedisPubSub) ping(ps *redis.PubSub, stopCh chan struct{}) {
	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			// A failed ping surfaces as a failed read in listen.
			_ = ps.Ping(context.Background())
		}
	}
}

// reopen replaces a dead subscription with a new one on every channel; its
// listener reports the gap once Redis confirms it.
func (r *RedisPubSub) reopen(oldStopCh chan struct{}) {
	r.mu.Lock()
	if r.stopCh != oldStopCh {
		// Shut down or already replaced.
		r.mu.Unlock()
		return
	}
	close(oldStopCh)
	if r.pubsub != nil {
		r.pubsub.Close()
	}
	r.pubsub = nil
	r.stopCh = nil
	if len(r.callbacks) == 0 {
		r.mu.Unlock()
		return
	}

	ps := r.client.Subscribe(context.Background())
	channels := make([]string, 0, len(r.callbacks))
	for channel := range r.callbacks {
		channels = append(channels, channel)
	}
	if err := ps.Subscribe(context.Background(), channels...); err != nil {
		// go-redis retries the subscription on the listener's next read.
		logging.Error("pubsub").Msgf("Failed to resubscribe after reconnect: %v", err)
	}
	r.pubsub = ps
	r.stopCh = make(chan struct{})
	go r.listen(ps, r.stopCh, true)
	r.mu.Unlock()
}

func (r *RedisPubSub) Unsubscribe(channel string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.pubsub == nil {
		return nil
	}

	if err := r.pubsub.Unsubscribe(context.Background(), channel); err != nil {
		return fmt.Errorf("failed to unsubscribe from channel: %w", err)
	}

	delete(r.callbacks, channel)

	if len(r.callbacks) == 0 {
		r.destroy()
	}

	return nil
}

// destroy cleans up the pubsub and signals the listener to stop
// Must be called with mu held
func (r *RedisPubSub) destroy() {
	if r.stopCh != nil {
		close(r.stopCh)
		r.stopCh = nil
	}
	if r.pubsub != nil {
		r.pubsub.Close()
		r.pubsub = nil
	}
}

func (r *RedisPubSub) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.destroy()
	return r.client.Close()
}
