package ws

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"

	"github.com/inference-sh/goutils/logging"
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

// DefaultLanes is how many messages a connection handles at once. Each lane
// handles its messages one at a time, in the order they were read.
const DefaultLanes = 20

// laneQueueSize is how many messages may wait for one lane before the reader
// blocks and backpressure reaches the peer through TCP.
const laneQueueSize = 256

// BaseConnection provides common functionality for both server and client connections
type BaseConnection struct {
	handlers    map[string]TypedHandler
	closeChan   chan struct{}
	ctx         context.Context
	msgBuffer   chan RawMessage
	lanes       []chan RawMessage
	orderingKey func(RawMessage) string
}

// NewBaseConnection creates a new base connection
func NewBaseConnection(ctx context.Context) BaseConnection {
	lanes := make([]chan RawMessage, DefaultLanes)
	for i := range lanes {
		lanes[i] = make(chan RawMessage, laneQueueSize)
	}
	return BaseConnection{
		handlers:    make(map[string]TypedHandler),
		closeChan:   make(chan struct{}),
		ctx:         ctx,
		msgBuffer:   make(chan RawMessage, 1000), // Buffer size can be adjusted
		lanes:       lanes,
		orderingKey: DefaultOrderingKey,
	}
}

// DefaultOrderingKey returns the id whose messages must be handled in the
// order they were read: the task, else the worker. Messages with neither
// share one lane.
func DefaultOrderingKey(msg RawMessage) string {
	var ids struct {
		TaskID   string `json:"task_id"`
		WorkerID string `json:"worker_id"`
	}
	if len(msg.Data) > 0 {
		_ = json.Unmarshal(msg.Data, &ids)
	}
	if ids.TaskID != "" {
		return ids.TaskID
	}
	return ids.WorkerID
}

// SetOrderingKey replaces DefaultOrderingKey (must be called before Listen).
func (b *BaseConnection) SetOrderingKey(fn func(RawMessage) string) {
	b.orderingKey = fn
}

// laneFor maps a message to its lane: the same key always gets the same lane.
func (b *BaseConnection) laneFor(msg RawMessage) int {
	h := fnv.New32a()
	h.Write([]byte(b.orderingKey(msg)))
	return int(h.Sum32() % uint32(len(b.lanes)))
}

// processMessages hands each message to its lane. Messages with the same
// ordering key are handled one at a time in the order they were read;
// different keys run in parallel, up to one handler per lane.
//
// Handling each message in its own goroutine (the previous design) let a later
// message about a task finish before an earlier one, which scrambled streamed
// output and raced lifecycle events.
func (b *BaseConnection) processMessages() {
	for _, lane := range b.lanes {
		go b.runLane(lane)
	}
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-b.closeChan:
			return
		case msg := <-b.msgBuffer:
			select {
			case b.lanes[b.laneFor(msg)] <- msg:
			case <-b.ctx.Done():
				return
			case <-b.closeChan:
				return
			}
		}
	}
}

func (b *BaseConnection) runLane(lane chan RawMessage) {
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-b.closeChan:
			return
		case msg := <-lane:
			b.dispatch(msg)
		}
	}
}

func (b *BaseConnection) dispatch(msg RawMessage) {
	if handler, ok := b.handlers[msg.Type]; ok {
		handler.Handle(b.ctx, msg)
	} else {
		logging.Error("ws").Msgf("No handler for message type: %s", msg.Type)
	}
}

// enqueue passes a message read from the socket to processMessages. When the
// buffer is full it waits rather than handling the message out of turn, so
// ordering holds and the peer is slowed through TCP backpressure.
func (b *BaseConnection) enqueue(ctx context.Context, done <-chan struct{}, msg RawMessage) bool {
	select {
	case b.msgBuffer <- msg:
		return true
	default:
	}
	logging.Warn("ws").Msgf("Message buffer full, waiting for handlers")
	select {
	case b.msgBuffer <- msg:
		return true
	case <-ctx.Done():
		return false
	case <-done:
		return false
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
