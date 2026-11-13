package ws

import "testing"

func isClosed(c *ServerConnection) bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// A connection replaced under the same id is closed, so its socket, its
// Listen goroutine and its buffers do not outlive the registration. The new
// one stays registered when the old one's handler then unregisters itself.
func TestHubRegister_closesSupersededConnection(t *testing.T) {
	h := NewHub("i1", nil)
	old := &ServerConnection{ID: "old", done: make(chan struct{})}
	next := &ServerConnection{ID: "new", done: make(chan struct{})}

	h.Register("engine-1", old)
	if isClosed(old) {
		t.Fatal("first registration closed the connection")
	}
	h.Register("engine-1", next)
	if !isClosed(old) {
		t.Fatal("superseded connection was left open")
	}
	if isClosed(next) {
		t.Fatal("new connection was closed")
	}

	if h.Unregister("engine-1", old) {
		t.Fatal("the superseded connection's unregister reported it still held the id")
	}
	if got, ok := h.GetConnection("engine-1"); !ok || got != next {
		t.Fatalf("new connection no longer registered: %v %v", got, ok)
	}
	if isClosed(next) {
		t.Fatal("new connection was closed by the old one's unregister")
	}
}

// Registering the same connection again is not a replacement.
func TestHubRegister_sameConnectionStaysOpen(t *testing.T) {
	h := NewHub("i1", nil)
	c := &ServerConnection{ID: "c", done: make(chan struct{})}
	h.Register("engine-1", c)
	h.Register("engine-1", c)
	if isClosed(c) {
		t.Fatal("re-registering a connection closed it")
	}
}
