package ws

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// A peer that stops reading must not hold Send: the write times out, the
// connection closes (Listen returns) and later Sends fail at once.
func TestServerSend_stalledPeerTimesOutAndCloses(t *testing.T) {
	conns := make(chan *ServerConnection, 1)
	listenDone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := NewServerConnection(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		if conn.WriteTimeout != DefaultServerWriteTimeout {
			t.Errorf("WriteTimeout = %s, want the default %s", conn.WriteTimeout, DefaultServerWriteTimeout)
		}
		conn.WriteTimeout = 200 * time.Millisecond
		conns <- conn
		conn.Listen(context.Background())
		close(listenDone)
	}))
	t.Cleanup(srv.Close)

	// The client never reads.
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	must(t, err)
	defer client.Close()
	conn := <-conns

	payload := strings.Repeat("a", 1<<20)
	result := make(chan error, 1)
	go func() {
		// Enough to fill both socket buffers many times over.
		for i := 0; i < 512; i++ {
			if err := conn.Send("blob", payload); err != nil {
				result <- err
				return
			}
		}
		result <- nil
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("512 MB went to a peer that never reads")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Send is still blocked on a peer that never reads")
	}
	select {
	case <-listenDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection stayed open after its write timed out")
	}
	if err := conn.Send("blob", "x"); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Send after the timeout = %v, want ErrNotConnected", err)
	}
}

// A peer that reads gets every message; the deadline is per write, so a
// connection that lives longer than WriteTimeout keeps sending.
func TestServerSend_readingPeerOutlivesWriteTimeout(t *testing.T) {
	conns := make(chan *ServerConnection, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := NewServerConnection(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		conn.WriteTimeout = 100 * time.Millisecond
		conns <- conn
		conn.Listen(context.Background())
	}))
	t.Cleanup(srv.Close)

	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	must(t, err)
	defer client.Close()
	conn := <-conns

	for i := 0; i < 4; i++ {
		must(t, conn.Send("tick", i))
		var msg RawMessage
		must(t, client.ReadJSON(&msg))
		if msg.Type != "tick" {
			t.Fatalf("got %q", msg.Type)
		}
		time.Sleep(60 * time.Millisecond)
	}
}
