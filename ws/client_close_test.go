package ws

import (
	"testing"

	"github.com/inference-sh/recws"
)

// A daemon whose handshake is refused never gets a *websocket.Conn. Closing it
// (Ctrl-C) used to send a close frame through that nil conn and panic.
func TestClientConnectionClose_neverConnected(t *testing.T) {
	c := &ClientConnection{conn: &recws.RecConn{}, done: make(chan struct{})}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// A second Close is a no-op.
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
