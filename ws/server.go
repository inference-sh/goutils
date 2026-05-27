package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/websocket"
	idgen "github.com/inference-sh/goutils/id"
	"github.com/inference-sh/goutils/logging"
)

// ServerConnection represents a WebSocket server connection
type ServerConnection struct {
	BaseConnection
	ID       string
	conn     *websocket.Conn
	sendChan chan *sendOp
	done     chan struct{}
}

// Ensure ServerConnection implements Connection interface
var _ Connection = (*ServerConnection)(nil)

// NewServerConnection creates a new WebSocket connection from an HTTP upgrade
func NewServerConnection(w http.ResponseWriter, r *http.Request) (*ServerConnection, error) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  32768,
		WriteBufferSize: 32768,
		CheckOrigin: func(r *http.Request) bool {
			return true // Override this in production
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade connection: %w", err)
	}

	connID := idgen.GenerateShortID(8)

	c := &ServerConnection{
		BaseConnection: NewBaseConnection(r.Context()),
		ID:             connID,
		conn:           conn,
		sendChan:       make(chan *sendOp),
		done:           make(chan struct{}),
	}

	go c.sendLoop()
	return c, nil
}

// Handle registers a handler for a specific message type
func (c *ServerConnection) Handle(msgType string, handler TypedHandler) {
	c.handlers[msgType] = handler
}

// Send sends a message through the WebSocket
func (c *ServerConnection) Send(msgType string, data any) error {
	op := &sendOp{
		msgType: msgType,
		data:    data,
		done:    make(chan error, 1),
	}

	select {
	case c.sendChan <- op:
		return <-op.done
	case <-c.done:
		return ErrNotConnected
	}
}

func (c *ServerConnection) sendLoop() {
	for {
		select {
		case <-c.done:
			return
		case op := <-c.sendChan:
			msg := RawMessage{
				Type: op.msgType,
				Data: json.RawMessage{},
			}

			if op.data != nil {
				jsonData, err := json.Marshal(op.data)
				if err != nil {
					op.done <- fmt.Errorf("failed to marshal message data: %w", err)
					continue
				}
				msg.Data = jsonData
			}

			op.done <- c.conn.WriteJSON(msg)
		}
	}
}

// Listen starts listening for incoming messages
func (c *ServerConnection) Listen(ctx context.Context) {
	logging.Info("ws").Msgf("Starting WebSocket server listener conn_id=%s", c.ID)
	defer c.Close()

	// Start message processor
	go c.BaseConnection.processMessages()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		default:
			var msg RawMessage
			err := c.conn.ReadJSON(&msg)
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					return
				}
				logging.Error("ws").Msgf("Error reading message conn_id=%s: %v", c.ID, err)
				return
			}

			// Send to message buffer for processing
			select {
			case c.msgBuffer <- msg:
				// Message queued successfully
			default:
				logging.Warn("ws").Msgf( "Message buffer full, processing synchronously")
				if handler, ok := c.handlers[msg.Type]; ok {
					handler.Handle(c.ctx, msg)
				} else {
					logging.Error("ws").Msgf( "No handler for message type: %s", msg.Type)
				}
			}
		}
	}
}

// Close closes the WebSocket connection
func (c *ServerConnection) Close() error {
	select {
	case <-c.done:
		return nil
	default:
		close(c.done)
		if c.conn != nil {
			return c.conn.Close()
		}
		return nil
	}
}
