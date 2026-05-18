package ws

import (
	"context"
	"encoding/json"
	"errors"

	"inference.sh/goutils/logging"
)

// ErrNotConnected is returned when trying to send a message while disconnected
var ErrNotConnected = errors.New("websocket: not connected")

// sendOp represents a send operation
type sendOp struct {
	msgType string
	data    any
	done    chan error
}

// Message represents a WebSocket message
type Message[T any] struct {
	Type string `json:"type"`           // Message type for routing
	Data T      `json:"data,omitempty"` // Typed payload
}

// RawMessage represents a raw WebSocket message before type parsing
type RawMessage struct {
	Type string          `json:"type"`           // Message type for routing
	Data json.RawMessage `json:"data,omitempty"` // Raw payload
}

// TypedHandler handles incoming messages with context
type TypedHandler interface {
	Handle(ctx context.Context, msg RawMessage)
}

// AsyncHandler provides concurrent message handling with worker pool
type AsyncHandler struct {
	handlerFunc  func(context.Context, RawMessage)
	workerPool   chan struct{}
	maxQueueSize int
}

// NewAsyncHandler creates a handler with a bounded worker pool
func NewAsyncHandler(fn func(context.Context, RawMessage), maxConcurrent, maxQueueSize int) *AsyncHandler {
	return &AsyncHandler{
		handlerFunc:  fn,
		workerPool:   make(chan struct{}, maxConcurrent),
		maxQueueSize: maxQueueSize,
	}
}

func (h *AsyncHandler) Handle(ctx context.Context, msg RawMessage) {
	select {
	case h.workerPool <- struct{}{}: // Acquire worker slot
		go func() {
			defer func() { <-h.workerPool }() // Release worker slot
			h.handlerFunc(ctx, msg)
		}()
	default:
		// Pool is full, handle synchronously to apply backpressure
		h.handlerFunc(ctx, msg)
	}
}

// Connection defines the common interface for both server and client connections
type Connection interface {
	Handle(msgType string, handler TypedHandler)
	Send(msgType string, data any) error
	Listen(ctx context.Context)
	Close() error
}

// BaseConnection provides common functionality for both server and client connections
type BaseConnection struct {
	handlers   map[string]TypedHandler
	closeChan  chan struct{}
	ctx        context.Context
	msgBuffer  chan RawMessage
	processing chan struct{}
}

// NewBaseConnection creates a new base connection
func NewBaseConnection(ctx context.Context) BaseConnection {
	return BaseConnection{
		handlers:   make(map[string]TypedHandler),
		closeChan:  make(chan struct{}),
		ctx:        ctx,
		msgBuffer:  make(chan RawMessage, 1000), // Buffer size can be adjusted
		processing: make(chan struct{}, 20),     // Concurrent message processing limit
	}
}

// processMessages handles messages from the buffer with bounded concurrency
func (b *BaseConnection) processMessages() {
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-b.closeChan:
			return
		case msg := <-b.msgBuffer:
			select {
			case b.processing <- struct{}{}: // Acquire processing slot
				go func(m RawMessage) {
					defer func() { <-b.processing }() // Release processing slot
					if handler, ok := b.handlers[m.Type]; ok {
						handler.Handle(b.ctx, m)
					} else {
						logging.Error("ws").Msgf( "No handler for message type: %s", m.Type)
					}
				}(msg)
			default:
				// Processing slots full, handle synchronously
				if handler, ok := b.handlers[msg.Type]; ok {
					handler.Handle(b.ctx, msg)
				} else {
					logging.Error("ws").Msgf( "No handler for message type: %s", msg.Type)
				}
			}
		}
	}
}

// Handle registers a handler for a specific message type
func (b *BaseConnection) Handle(msgType string, handler TypedHandler) {
	b.handlers[msgType] = handler
}

// SetContext updates the connection's context (must be called before Listen)
func (b *BaseConnection) SetContext(ctx context.Context) {
	b.ctx = ctx
}

// HandleTyped is a helper function to register a typed handler for any connection type
func HandleTyped[T any, C Connection](conn C, msgType string, fn func(context.Context, Message[T])) {
	conn.Handle(msgType, &messageHandler[T]{fn: fn})
}

// messageHandler is an internal type that implements TypedHandler
type messageHandler[T any] struct {
	fn func(context.Context, Message[T])
}

// Handle implements TypedHandler
func (h *messageHandler[T]) Handle(ctx context.Context, raw RawMessage) {
	var data T
	if len(raw.Data) == 0 {
		h.fn(ctx, Message[T]{Type: raw.Type, Data: data})
		return
	}
	if err := json.Unmarshal(raw.Data, &data); err != nil {
		logging.Error("ws").Msgf( "Failed to unmarshal message data: %v", err)
		return
	}
	h.fn(ctx, Message[T]{Type: raw.Type, Data: data})
}

// HandleFunc creates a typed message handler
func HandleFunc[T any](fn func(context.Context, Message[T])) TypedHandler {
	return &messageHandler[T]{fn: fn}
}
