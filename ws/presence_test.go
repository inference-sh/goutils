package ws

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestStore(t *testing.T) (*RedisConnectionStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return &RedisConnectionStore{client: client}, mr
}

func holder(t *testing.T, s *RedisConnectionStore, id string) string {
	t.Helper()
	got, err := s.Find(id)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		return ""
	}
	return *got
}

// The cross-instance race: a machine moves from instance A to B, and A's close
// handler runs after B registered. A must not erase B's lease.
func TestUnregister_onlyTheHolderReleases(t *testing.T) {
	s, _ := newTestStore(t)
	must(t, s.Register("remote-1", "instance-a"))
	must(t, s.Register("remote-1", "instance-b")) // reconnected elsewhere

	owned, err := s.Unregister("remote-1", "instance-a")
	must(t, err)
	if owned {
		t.Fatal("instance-a no longer holds the lease but released it")
	}
	if h := holder(t, s, "remote-1"); h != "instance-b" {
		t.Fatalf("holder = %q, want instance-b", h)
	}

	owned, err = s.Unregister("remote-1", "instance-b")
	must(t, err)
	if !owned || holder(t, s, "remote-1") != "" {
		t.Fatal("the holder's release must remove the lease")
	}
}

// Refresh renews the holder's lease, reclaims a lapsed one, and never takes
// another instance's.
func TestRefresh_renewsReclaimsNeverSteals(t *testing.T) {
	s, mr := newTestStore(t)
	must(t, s.Register("remote-1", "instance-a"))

	mr.FastForward(connectionTTL - time.Second)
	owned, err := s.Refresh("remote-1", "instance-a")
	must(t, err)
	mr.FastForward(connectionTTL - time.Second)
	if !owned || holder(t, s, "remote-1") != "instance-a" {
		t.Fatal("a renewed lease must outlive its original TTL")
	}

	mr.FastForward(connectionTTL + time.Second) // lapsed while the socket stayed open
	if holder(t, s, "remote-1") != "" {
		t.Fatal("lease should have lapsed")
	}
	owned, err = s.Refresh("remote-1", "instance-a")
	must(t, err)
	if !owned || holder(t, s, "remote-1") != "instance-a" {
		t.Fatal("the instance holding the socket must reclaim a lapsed lease")
	}

	must(t, s.Register("remote-1", "instance-b"))
	owned, err = s.Refresh("remote-1", "instance-a")
	must(t, err)
	if owned || holder(t, s, "remote-1") != "instance-b" {
		t.Fatal("refresh must not take another instance's lease")
	}
}

// A crashed instance renews nothing, so its leases are gone within the TTL.
func TestLease_lapsesWithoutRenewal(t *testing.T) {
	s, mr := newTestStore(t)
	must(t, s.Register("remote-1", "instance-a"))
	mr.FastForward(connectionTTL + time.Second)
	if holder(t, s, "remote-1") != "" {
		t.Fatal("an unrenewed lease must lapse after the TTL")
	}
}

func TestLive_reportsHoldersInOneCall(t *testing.T) {
	s, _ := newTestStore(t)
	must(t, s.Register("remote-1", "instance-a"))
	must(t, s.Register("remote-2", "instance-b"))

	live, err := s.Live([]string{"remote-1", "remote-2", "remote-3"})
	must(t, err)
	if len(live) != 2 || live["remote-1"] != "instance-a" || live["remote-2"] != "instance-b" {
		t.Fatalf("live = %v", live)
	}
	if live, err := s.Live(nil); err != nil || len(live) != 0 {
		t.Fatalf("empty query: %v, %v", live, err)
	}
}

func stubConn(id string) *ServerConnection {
	return &ServerConnection{ID: id, done: make(chan struct{})}
}

// Two instances sharing one store: the hub reports a disconnect only when the
// connection really left, not when it moved to the other instance.
func TestHub_unregisterReportsOwnership(t *testing.T) {
	s, _ := newTestStore(t)
	a := &Hub{instanceID: "instance-a", connectionStore: s, ttlKeys: map[string]struct{}{}}
	b := &Hub{instanceID: "instance-b", connectionStore: s, ttlKeys: map[string]struct{}{}}

	connA := stubConn("conn-a")
	a.Register("remote-1", connA)
	b.Register("remote-1", stubConn("conn-b")) // the machine reconnected to b

	if a.Unregister("remote-1", connA) {
		t.Fatal("a's late close must not count as a disconnect: the machine is on b")
	}
	live, err := a.Live([]string{"remote-1"})
	must(t, err)
	if live["remote-1"] != "instance-b" {
		t.Fatalf("live = %v, want remote-1 on instance-b", live)
	}

	if !b.Unregister("remote-1", nil) {
		t.Fatal("the holder's close is a real disconnect")
	}
	if live, _ := b.Live([]string{"remote-1"}); len(live) != 0 {
		t.Fatalf("live = %v after the holder closed", live)
	}
}

// Without a store (tests, self-host) presence is this instance's connections.
func TestHub_localPresence(t *testing.T) {
	h := &Hub{instanceID: "solo", ttlKeys: map[string]struct{}{}}
	conn := stubConn("conn-1")
	h.Register("remote-1", conn)

	live, err := h.Live([]string{"remote-1", "remote-2"})
	must(t, err)
	if len(live) != 1 || live["remote-1"] != "solo" {
		t.Fatalf("live = %v", live)
	}
	if !h.Unregister("remote-1", conn) {
		t.Fatal("a local close is a real disconnect")
	}
	if live, _ := h.Live([]string{"remote-1"}); len(live) != 0 {
		t.Fatalf("live = %v after close", live)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
