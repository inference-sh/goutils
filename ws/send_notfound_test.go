package ws

import (
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// A send to a connection no instance holds is ErrConnectionNotFound, so a
// caller can tell "offline" from a failed send with errors.Is; the error
// still names the connection.
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
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := NewRedisConnectionStore(client)
	hub := NewHub("instance-a", store)
	if err := hub.SendToConnection("remote-1", "ping", nil); !errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("held nowhere: %v, want ErrConnectionNotFound", err)
	}

	// Held by another instance: forwarded, no error.
	must(t, store.Register("remote-1", "instance-b"))
	if err := hub.SendToConnection("remote-1", "ping", map[string]int{"n": 1}); err != nil {
		t.Fatalf("held elsewhere: %v", err)
	}
}
