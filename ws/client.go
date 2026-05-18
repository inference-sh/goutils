package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/inference-sh/recws"
	"github.com/inference-sh/goutils/logging"
)

// ClientConnection represents a WebSocket client connection with auto-reconnect
type ClientConnection struct {
	BaseConnection
	conn     *recws.RecConn
	sendChan chan *sendOp
	done     chan struct{}
}

// Ensure ClientConnection implements Connection interface
var _ Connection = (*ClientConnection)(nil)

// ClientOptions contains configurable options for WebSocket client connections
type ClientOptions struct {
	Headers           http.Header
	HandshakeTimeout  time.Duration
	EnableCompression bool
	ReadBufferSize    int
	WriteBufferSize   int
	// RecIntvlMin specifies the initial reconnecting interval
	RecIntvlMin time.Duration
	// RecIntvlMax specifies the maximum reconnecting interval
	RecIntvlMax time.Duration
	// RecIntvlFactor specifies the rate of increase of the reconnection interval
	RecIntvlFactor float64
	// KeepAliveTimeout is an interval for sending ping/pong messages
	KeepAliveTimeout time.Duration
}

// DefaultClientOptions returns the default client connection options
func DefaultClientOptions() ClientOptions {
	return ClientOptions{
		Headers:           make(http.Header),
		HandshakeTimeout:  10 * time.Second,
		EnableCompression: true,
		ReadBufferSize:    32768,
		WriteBufferSize:   32768,
		RecIntvlMin:       2 * time.Second,
		RecIntvlMax:       30 * time.Second,
		RecIntvlFactor:    1.5,
		KeepAliveTimeout:  60 * time.Second,
	}
}

// NewClientConnection creates a new WebSocket client connection with default options
func NewClientConnection(url string, header http.Header) (*ClientConnection, error) {
	options := DefaultClientOptions()
	options.Headers = header
	return NewClientConnectionWithOptions(url, options)
}

type slogWrapper struct{}

func (l *slogWrapper) Debug(msg string, args ...any) {
	logging.Debug("ws").Msgf(msg, args...)
}

func (l *slogWrapper) Info(msg string, args ...any) {
	logging.Info("ws").Msgf(msg, args...)
}

func (l *slogWrapper) Warn(msg string, args ...any) {
	logging.Warn("ws").Msgf(msg, args...)
}

func (l *slogWrapper) Error(msg string, args ...any) {
	logging.Error("ws").Msgf(msg, args...)
}

// NewClientConnectionWithOptions creates a new WebSocket client connection with custom options
func NewClientConnectionWithOptions(url string, options ClientOptions) (*ClientConnection, error) {
	// Create a logger adapter that converts our utils.Logger to slog interface
	slogAdapter := &slogWrapper{}

	recConn := &recws.RecConn{
		HandshakeTimeout: options.HandshakeTimeout,
		RecIntvlMin:      options.RecIntvlMin,
		RecIntvlMax:      options.RecIntvlMax,
		RecIntvlFactor:   options.RecIntvlFactor,
		KeepAliveTimeout: options.KeepAliveTimeout,
		Logger:           slogAdapter,
	}

	c := &ClientConnection{
		BaseConnection: NewBaseConnection(context.Background()),
		conn:           recConn,
		sendChan:       make(chan *sendOp),
		done:           make(chan struct{}),
	}

	logging.Info("ws").Msgf( "Starting WebSocket client send loop")
	go c.sendLoop()
	logging.Info("ws").Msgf( "Starting WebSocket client dial")
	recConn.Dial(url, options.Headers)
	logging.Info("ws").Msgf( "WebSocket client dialed")
	return c, nil
}

// Handle registers a handler for a specific message type
func (c *ClientConnection) Handle(msgType string, handler TypedHandler) {
	c.handlers[msgType] = handler
}

// Send sends a message through the WebSocket
func (c *ClientConnection) Send(msgType string, data any) error {
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

func (c *ClientConnection) sendLoop() {
	for {
		select {
		case <-c.done:
			return
		case op := <-c.sendChan:
			if !c.conn.IsConnected() {
				op.done <- ErrNotConnected
				continue
			}

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
func (c *ClientConnection) Listen(ctx context.Context) {
	logging.Info("ws").Msgf( "Starting WebSocket client listener")
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
			if !c.conn.IsConnected() {
				time.Sleep(time.Second) // Wait before checking connection again
				continue
			}

			var msg RawMessage
			err := c.conn.ReadJSON(&msg)
			if err != nil {
				logging.Error("ws").Msgf( "Error reading message: %v", err)
				continue // Let recws handle reconnection
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
func (c *ClientConnection) Close() error {
	select {
	case <-c.done:
		return nil
	default:
		close(c.done)
		c.conn.Close()
		return nil
	}
}
