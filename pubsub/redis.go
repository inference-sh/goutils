package pubsub

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/inference-sh/goutils/logging"
)

// RedisPubSub implements the ws.PubSub interface using Redis
type RedisPubSub struct {
	client    *redis.Client
	pubsub    *redis.PubSub
	mu        sync.RWMutex
	callbacks map[string]func(message []byte)
	stopCh    chan struct{} // Closed to signal intentional shutdown
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
		go r.listen()
	}

	if err := r.pubsub.Subscribe(context.Background(), channel); err != nil {
		delete(r.callbacks, channel)
		return fmt.Errorf("failed to subscribe to channel: %w", err)
	}

	return nil
}

func (r *RedisPubSub) listen() {
	r.mu.RLock()
	pubsub := r.pubsub
	stopCh := r.stopCh
	r.mu.RUnlock()

	if pubsub == nil {
		return
	}

	ch := pubsub.Channel()

	// Health check
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			// Intentional shutdown - exit without reconnecting
			return

		case <-ticker.C:
			r.mu.RLock()
			ps := r.pubsub
			r.mu.RUnlock()

			if ps != nil {
				if err := ps.Ping(context.Background()); err != nil {
					logging.Info("pubsub").Msgf( "Redis PubSub ping failed, attempting reconnect")
					r.reconnect(stopCh)
					return
				}
			}

		case msg, ok := <-ch:
			if !ok {
				// Channel closed - check if intentional before reconnecting
				select {
				case <-stopCh:
					// Intentional shutdown
					return
				default:
					// Unexpected disconnect - reconnect
					logging.Info("pubsub").Msgf( "Redis PubSub channel closed, attempting reconnect")
					r.reconnect(stopCh)
					return
				}
			}

			r.mu.RLock()
			callback, exists := r.callbacks[msg.Channel]
			r.mu.RUnlock()

			if !exists {
				continue
			}

			callback([]byte(msg.Payload))
		}
	}
}

func (r *RedisPubSub) reconnect(oldStopCh chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// If stopCh changed, another goroutine handled this
	if r.stopCh != oldStopCh {
		return
	}

	// Nothing to reconnect for
	if len(r.callbacks) == 0 {
		logging.Info("pubsub").Msgf( "Redis PubSub reconnect skipped: no active subscriptions")
		return
	}

	// Clean up old
	if r.pubsub != nil {
		r.pubsub.Close()
	}

	// Create new
	r.pubsub = r.client.Subscribe(context.Background())
	r.stopCh = make(chan struct{})

	for channel := range r.callbacks {
		if err := r.pubsub.Subscribe(context.Background(), channel); err != nil {
			logging.Error("pubsub").Msgf( "Failed to resubscribe to channel %s: %v", channel, err)
		}
	}

	logging.Info("pubsub").Msgf( "Redis PubSub reconnected successfully")
	go r.listen()
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
