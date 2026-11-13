package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// limitServer runs Listen with readLimit (0 keeps the default), hands each
// message to got, and reports when Listen returns.
func limitServer(t *testing.T, readLimit int64) (url string, got <-chan int, closed <-chan struct{}) {
	t.Helper()
	msgs := make(chan int, 4)
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := NewServerConnection(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		if conn.ReadLimit != DefaultServerReadLimit {
			t.Errorf("ReadLimit = %d, want the default %d", conn.ReadLimit, DefaultServerReadLimit)
		}
		if readLimit != 0 {
			conn.ReadLimit = readLimit
		}
		conn.Handle("blob", blobHandler(msgs))
		conn.Listen(context.Background())
		close(done)
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), msgs, done
}

type blobHandler chan int

func (h blobHandler) Handle(_ context.Context, msg RawMessage) { h <- len(msg.Data) }

func blob(n int) RawMessage {
	return RawMessage{Type: "blob", Data: []byte(`"` + strings.Repeat("a", n) + `"`)}
}

// A message over ReadLimit closes the connection and never reaches
// a handler; one under it is delivered.
func TestServerListen_readLimit(t *testing.T) {
	url, got, closed := limitServer(t, 64<<10)
	c, _, err := websocket.DefaultDialer.Dial(url, nil)
	must(t, err)
	defer c.Close()

	must(t, c.WriteJSON(blob(1<<10)))
	select {
	case n := <-got:
		if n != 1<<10+2 {
			t.Fatalf("handler got %d bytes", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a message under the limit was not delivered")
	}

	// The server closes as soon as it has read past the limit, so the rest
	// of this write may fail with a reset.
	_ = c.WriteJSON(blob(1 << 20))
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Listen kept a peer that sent a message over the limit")
	}
	select {
	case n := <-got:
		t.Fatalf("the oversized message reached a handler (%d bytes)", n)
	default:
	}
}

// The default leaves room for what peers send today: a multi-megabyte
// message goes through untouched.
func TestServerListen_defaultReadLimitTakesLargeMessages(t *testing.T) {
	url, got, _ := limitServer(t, 0)
	c, _, err := websocket.DefaultDialer.Dial(url, nil)
	must(t, err)
	defer c.Close()

	const size = 24 << 20
	must(t, c.WriteJSON(blob(size)))
	select {
	case n := <-got:
		if n != size+2 {
			t.Fatalf("handler got %d bytes, want %d", n, size+2)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a 24 MB message was not delivered under the default limit")
	}
}
