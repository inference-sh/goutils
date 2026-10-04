package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
)

// A message for a connection held by another instance reaches it, also when
// that instance runs more than one hub (engines and remotes, in that order,
// as the api does): each hub on the instance gets every forwarded message,
// and the one that holds the connection delivers it. With one subscriber per
// channel the remote hub replaced the engine hub, and every message forwarded
// to an engine was dropped (the stuck-task bursts at each api deploy).
func TestHub_forwardsToAConnectionOnAnotherInstance(t *testing.T) {
	mr := miniredis.RunT(t)
	store := func() *RedisConnectionStore {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = client.Close() })
		return NewRedisConnectionStore(client)
	}
	// Instance a: one store, two hubs, the engine hub first.
	storeA := store()
	engines := NewHub("instance-a", storeA)
	_ = NewHub("instance-a", storeA)
	// Instance b: where the scheduler runs.
	scheduler := NewHub("instance-b", store())

	registered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := NewServerConnection(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		engines.Register("engine-1", conn)
		close(registered)
		conn.Listen(context.Background())
	}))
	defer srv.Close()

	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	must(t, err)
	defer client.Close()
	<-registered

	deadline := time.Now().Add(5 * time.Second)
	got := make(chan RawMessage, 1)
	go func() {
		var msg RawMessage
		if err := client.ReadJSON(&msg); err == nil {
			got <- msg
		}
	}()
	// Redis delivers to subscriptions that exist when the message is
	// published; resend until instance a's subscription is up.
	for {
		must(t, scheduler.SendToConnection("engine-1", "task_run", map[string]string{"task_id": "t1"}))
		select {
		case msg := <-got:
			if msg.Type != "task_run" {
				t.Fatalf("got %q", msg.Type)
			}
			return
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the message for engine-1 never reached it")
		}
	}
}

// A shutting-down instance sends its peers away with "going away" (1001), and
// knows when each has reconnected to another instance.
func TestHub_leaveAllAndWaitMoved(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := NewRedisConnectionStore(client)
	old := NewHub("instance-old", store)
	next := NewHub("instance-new", store)

	registered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := NewServerConnection(w, r)
		if err != nil {
			t.Error(err)
			return
		}
		old.Register("engine-1", conn)
		close(registered)
		conn.Listen(context.Background())
		old.Unregister("engine-1", conn)
	}))
	defer srv.Close()
	peer, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	must(t, err)
	defer peer.Close()
	<-registered

	ids := old.LeaveAll()
	if len(ids) != 1 || ids[0] != "engine-1" {
		t.Fatalf("LeaveAll = %v", ids)
	}
	_, _, err = peer.ReadMessage()
	if !websocket.IsCloseError(err, websocket.CloseGoingAway) {
		t.Fatalf("the peer is told the server is going away, got %v", err)
	}

	// Not moved yet: the wait gives up at its deadline.
	short, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if old.WaitMoved(short, ids) {
		t.Fatal("engine-1 has not reconnected anywhere yet")
	}

	// The peer reconnects to the new instance.
	next.Register("engine-1", stubConn("conn-new"))
	ctx, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if !old.WaitMoved(ctx, ids) {
		t.Fatal("engine-1 is held by the new instance")
	}
}
