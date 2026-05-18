package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"inference.sh/goutils/logging"
)

// Hub manages all active WebSocket server connections
type Hub struct {
	// Connections mapped by ID (e.g., engine ID)
	connections sync.Map
	// Optional PubSub interface for scaling
	connectionStore ConnectionStore
	// Instance ID to identify this hub instance
	instanceID string

	// pubsub ttl keys
	ttlMu   sync.RWMutex
	ttlKeys map[string]struct{}
}

// NewHub creates a new connection hub
func NewHub(instanceID string, connectionStore ConnectionStore) *Hub {
	hub := &Hub{
		instanceID:      instanceID,
		connectionStore: connectionStore,
		ttlKeys:         make(map[string]struct{}),
	}

	if connectionStore != nil {
		// Subscribe to direct messages for this instance
		connectionStore.Subscribe(fmt.Sprintf("instance_%s", instanceID), func(message []byte) {
			var msg struct {
				ConnectionID string          `json:"connection_id"`
				Type         string          `json:"type"`
				Data         json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(message, &msg); err != nil {
				logging.Error("ws").Msgf( "failed to unmarshal instance message: %v", err)
				return
			}

			// Forward message to local connection
			if conn, ok := hub.GetConnection(msg.ConnectionID); ok {
				var data any
				if len(msg.Data) > 0 {
					if err := json.Unmarshal(msg.Data, &data); err != nil {
						logging.Error("ws").Msgf( "failed to unmarshal message data: %v", err)
						return
					}
				}
				conn.Send(msg.Type, data)
			}
		})

		go hub.startTTLRefresh()
	}

	return hub
}

func (h *Hub) startTTLRefresh() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			h.ttlMu.RLock()
			for id := range h.ttlKeys {
				_ = h.connectionStore.Refresh(id)
			}
			h.ttlMu.RUnlock()
		}
	}()
}

// Register adds a server connection to the hub with an identifier
func (h *Hub) Register(id string, conn *ServerConnection) {
	h.connections.Store(id, conn)
	h.ttlMu.Lock()
	h.ttlKeys[id] = struct{}{}
	h.ttlMu.Unlock()
	if h.connectionStore != nil {
		if err := h.connectionStore.Register(id, h.instanceID); err != nil {
			logging.Error("ws").Msgf( "failed to register connection in pubsub: %v", err)
		}
	}
}

// Unregister removes a connection from the hub.
// If conn is provided, only removes if it matches the current connection (prevents race on reconnect).
func (h *Hub) Unregister(id string, conn *ServerConnection) {
	if conn != nil {
		// Only unregister if this is still the active connection
		current, loaded := h.connections.Load(id)
		if !loaded || current != conn {
			return // Connection was replaced by a newer one
		}
	}

	if c, ok := h.connections.LoadAndDelete(id); ok {
		if sc, ok := c.(*ServerConnection); ok {
			sc.Close()
		}
	}
	h.ttlMu.Lock()
	delete(h.ttlKeys, id)
	h.ttlMu.Unlock()
	if h.connectionStore != nil {
		if err := h.connectionStore.Unregister(id); err != nil {
			logging.Error("ws").Msgf( "failed to unregister connection in pubsub: %v", err)
		}
	}
}

// ConnectionState represents the state of a connection
type ConnectionState int

const (
	ConnectionNotFound ConnectionState = iota
	ConnectionLocal
	ConnectionRemote
)

// GetConnectionState returns detailed information about a connection's state
func (h *Hub) GetConnectionState(id string) ConnectionState {
	// Check local first
	if _, ok := h.connections.Load(id); ok {
		return ConnectionLocal
	}

	// If we have pubsub, check other instances
	if h.connectionStore != nil {
		instanceID, err := h.connectionStore.Find(id)
		if err != nil {
			logging.Error("ws").Msgf( "Failed to find connection: %v", err)
			return ConnectionNotFound
		}
		if instanceID != nil {
			return ConnectionRemote
		}
	} else {
		logging.Info("ws").Msgf( "No pubsub found, only checking local connections")
	}

	return ConnectionNotFound
}

// GetConnection retrieves a server connection by ID
func (h *Hub) GetConnection(id string) (*ServerConnection, bool) {
	state := h.GetConnectionState(id)

	switch state {
	case ConnectionLocal:
		if conn, ok := h.connections.Load(id); ok {
			if c, ok := conn.(*ServerConnection); ok {
				return c, true
			}
		}
	case ConnectionRemote:
		logging.Info("ws").Msgf( "Connection found on another instance, returning false")
		return nil, false
	case ConnectionNotFound:
		logging.Info("ws").Msgf( "Connection not found anywhere")
		return nil, false
	}

	return nil, false
}

// IsConnectionAvailable checks if a connection exists either locally or remotely
func (h *Hub) IsConnectionAvailable(id string) bool {
	// Check local first
	if _, ok := h.connections.Load(id); ok {
		return true
	}

	// If we have pubsub, check other instances
	if h.connectionStore != nil {
		instanceID, err := h.connectionStore.Find(id)
		if err != nil {
			logging.Error("ws").Msgf( "failed to find connection: %v", err)
			return false
		}
		return instanceID != nil
	}

	return false
}

// CanSendMessage checks if we can send a message to this connection (either locally or remotely)
func (h *Hub) CanSendMessage(id string) bool {
	// Check local first
	if _, ok := h.connections.Load(id); ok {
		return true
	}
	// If we have pubsub, check other instances
	if h.connectionStore != nil {
		instanceID, err := h.connectionStore.Find(id)
		if err != nil {
			logging.Error("ws").Msgf( "Failed to find connection: %v", err)
			return false
		}
		if instanceID == nil {
			return false
		}
		return true
	}

	return false
}

// SendToConnection sends a message to a specific connection
func (h *Hub) SendToConnection(id string, msgType string, data any) error {
	state := h.GetConnectionState(id)

	switch state {
	case ConnectionLocal:
		if conn, ok := h.GetConnection(id); ok {
			return conn.Send(msgType, data)
		}
	case ConnectionRemote:
		// If not local and we have pubsub, try to find it on other instances
		instanceID, err := h.connectionStore.Find(id)
		if err != nil || instanceID == nil {
			return fmt.Errorf("failed to find connection: %w", err)
		}

		// Marshal the data
		var dataBytes []byte
		if data != nil {
			var err error
			dataBytes, err = json.Marshal(data)
			if err != nil {
				return fmt.Errorf("failed to marshal message data: %w", err)
			}
		}

		// Forward the message to the correct instance
		if err := h.connectionStore.SendToInstance(*instanceID, id, msgType, dataBytes); err != nil {
			return fmt.Errorf("failed to forward message: %w", err)
		}
		return nil
	case ConnectionNotFound:
		return fmt.Errorf("connection not found: %s", id)
	}

	return fmt.Errorf("connection not found: %s", id)
}

// BroadcastToChannel sends a message to all connections subscribed to a channel
func (h *Hub) BroadcastToChannel(channel string, msgType string, data any) error {
	if h.connectionStore != nil {
		// If we have a PubSub system, use it for scalable broadcasting
		msg := RawMessage{Type: msgType}
		if data != nil {
			jsonData, err := json.Marshal(data)
			if err != nil {
				return fmt.Errorf("failed to marshal message: %w", err)
			}
			msg.Data = jsonData
		}

		msgBytes, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed to marshal message: %w", err)
		}
		return h.connectionStore.Publish(channel, msgBytes)
	}

	// Local broadcast if no PubSub
	h.connections.Range(func(key, value any) bool {
		if conn, ok := value.(*ServerConnection); ok {
			conn.Send(msgType, data)
		}
		return true
	})
	return nil
}

// BroadcastToAll sends a message to all connected clients
func (h *Hub) BroadcastToAll(msgType string, data any) error {
	h.connections.Range(func(key, value any) bool {
		if conn, ok := value.(*ServerConnection); ok {
			conn.Send(msgType, data)
		}
		return true
	})
	return nil
}

// SubscribeToChannel subscribes to messages on a channel
func (h *Hub) SubscribeToChannel(ctx context.Context, channel string, callback func(msg RawMessage)) error {
	if h.connectionStore == nil {
		return fmt.Errorf("no pubsub system configured")
	}

	return h.connectionStore.Subscribe(channel, func(data []byte) {
		var msg RawMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			// Log error but don't stop processing
			logging.Error("ws").Msgf( "failed to unmarshal message: %v", err)
			return
		}
		callback(msg)
	})
}

// UnsubscribeFromChannel unsubscribes from a channel
func (h *Hub) UnsubscribeFromChannel(channel string) error {
	if h.connectionStore == nil {
		return fmt.Errorf("no pubsub system configured")
	}
	return h.connectionStore.Unsubscribe(channel)
}

// GetAllConnections returns all active connections
func (h *Hub) GetAllConnections() []*ServerConnection {
	var connections []*ServerConnection
	h.connections.Range(func(key, value any) bool {
		if conn, ok := value.(*ServerConnection); ok {
			connections = append(connections, conn)
		}
		return true
	})
	return connections
}

// GetConnectionCount returns the number of active connections
func (h *Hub) GetConnectionCount() int {
	count := 0
	h.connections.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}
