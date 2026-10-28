package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// deadlineServer runs Listen with readTimeout and reports when it returns.
func deadlineServer(t *testing.T, readTimeout time.Duration) (url string, closed <-chan time.Time) {
	t.Helper()
	ch := make(chan time.Time, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := NewServerConnection(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		conn.ReadTimeout = readTimeout
		conn.Listen(context.Background())
		ch <- time.Now()
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), ch
}

func dialDeadline(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.DefaultDialer.Dial(url, nil)
	must(t, err)
	t.Cleanup(func() { c.Close() })
	// A reader so control frames (the server's pongs) are handled.
	go func() {
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}()
	return c
}

// A peer that sends nothing, a hung one, has its socket closed after the
// read timeout instead of holding Listen forever.
func TestServerListen_silentPeerClosed(t *testing.T) {
	const timeout = 150 * time.Millisecond
	url, closed := deadlineServer(t, timeout)
	start := time.Now()
	dialDeadline(t, url)

	select {
	case at := <-closed:
		if gap := at.Sub(start); gap < timeout-20*time.Millisecond {
			t.Fatalf("closed after %v, before the %v timeout", gap, timeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("silent peer: Listen never returned")
	}
}

// Pings alone keep a peer open, and each one is still answered.
func TestServerListen_pingsKeepPeer(t *testing.T) {
	const timeout = 60 * time.Millisecond
	url, closed := deadlineServer(t, timeout)
	c := dialDeadline(t, url)
	var pongs atomic.Int32
	c.SetPongHandler(func(string) error { pongs.Add(1); return nil })

	end := time.Now().Add(15 * timeout)
	for time.Now().Before(end) {
		must(t, c.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)))
		select {
		case <-closed:
			t.Fatal("pinging peer was closed")
		case <-time.After(timeout / 3):
		}
	}
	if pongs.Load() == 0 {
		t.Fatal("pings were not answered")
	}
}

// Messages alone keep a peer open.
func TestServerListen_messagesKeepPeer(t *testing.T) {
	const timeout = 60 * time.Millisecond
	url, closed := deadlineServer(t, timeout)
	c := dialDeadline(t, url)

	end := time.Now().Add(15 * timeout)
	for time.Now().Before(end) {
		must(t, c.WriteJSON(RawMessage{Type: "tick"}))
		select {
		case <-closed:
			t.Fatal("streaming peer was closed")
		case <-time.After(timeout / 3):
		}
	}
}

// Unsolicited pongs count too (a browser or a client answering its own
// heartbeat).
func TestServerListen_pongsKeepPeer(t *testing.T) {
	const timeout = 60 * time.Millisecond
	url, closed := deadlineServer(t, timeout)
	c := dialDeadline(t, url)

	end := time.Now().Add(15 * timeout)
	for time.Now().Before(end) {
		must(t, c.WriteControl(websocket.PongMessage, nil, time.Now().Add(time.Second)))
		select {
		case <-closed:
			t.Fatal("ponging peer was closed")
		case <-time.After(timeout / 3):
		}
	}
}
