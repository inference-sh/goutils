package ws

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// A send to a connection no instance holds is ErrConnectionNotFound, so a
// caller can tell "offline" from a failed send with errors.Is; the error
// still names the connection. A failed store lookup is not "offline".
func TestSendToConnection_notFound(t *testing.T) {
	alone := NewHub("instance-a", nil)
	err := alone.SendToConnection("remote-1", "ping", nil)
	if !errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("no store: %v, want ErrConnectionNotFound", err)
	}
	if err.Error() != "connection not found: remote-1" {
		t.Errorf("message %q", err.Error())
	}

	mr := miniredis.RunT(t)
	store := func() *RedisConnectionStore {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = client.Close() })
		return NewRedisConnectionStore(client)
	}
	storeA := store()
	hub := NewHub("instance-a", storeA)
	if err := hub.SendToConnection("remote-1", "ping", nil); !errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("held nowhere: %v, want ErrConnectionNotFound", err)
	}

	// A lease naming this instance with no connection here (it went and
	// its lease has not lapsed): not found, not a message to itself.
	must(t, storeA.Register("remote-1", "instance-a"))
	if err := hub.SendToConnection("remote-1", "ping", nil); !errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("stale lease here: %v, want ErrConnectionNotFound", err)
	}

	// Held by another instance: forwarded to it.
	storeB := store()
	got := make(chan []byte, 1)
	must(t, storeB.Subscribe("instance_instance-b", func(m []byte) { got <- m }))
	must(t, storeA.Register("remote-1", "instance-b"))
	if err := hub.SendToConnection("remote-1", "ping", map[string]int{"n": 1}); err != nil {
		t.Fatalf("held elsewhere: %v", err)
	}
	select {
	case m := <-got:
		var msg struct {
			ConnectionID string          `json:"connection_id"`
			Type         string          `json:"type"`
			Data         json.RawMessage `json:"data"`
		}
		must(t, json.Unmarshal(m, &msg))
		if msg.ConnectionID != "remote-1" || msg.Type != "ping" || string(msg.Data) != `{"n":1}` {
			t.Fatalf("forwarded %s", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing reached instance-b")
	}

	// The store is down: an error, but not "offline".
	mr.Close()
	err = hub.SendToConnection("remote-1", "ping", nil)
	if err == nil || errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("store down: %v, want a lookup error", err)
	}
}
