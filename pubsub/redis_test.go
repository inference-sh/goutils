package pubsub

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisPubSub_ReportsAGapAfterTheConnectionDropsAndDeliversAgain(t *testing.T) {
	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr(), MaxRetries: -1})
	ps := NewRedisPubSub(client)
	t.Cleanup(func() { _ = ps.Close() })

	got := make(chan string, 16)
	gaps := make(chan struct{}, 4)
	ps.OnGap(func() { gaps <- struct{}{} })
	if err := ps.Subscribe("ch", func(m []byte) { got <- string(m) }); err != nil {
		t.Fatal(err)
	}

	publishUntilReceived := func(want string) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			if err := ps.Publish("ch", []byte(want)); err != nil {
				t.Logf("publish: %v", err)
			}
			select {
			case m := <-got:
				if m == want {
					return
				}
			case <-time.After(50 * time.Millisecond):
			case <-deadline:
				t.Fatalf("never received %q", want)
			}
		}
	}

	publishUntilReceived("before")
	select {
	case <-gaps:
		t.Fatal("no gap while connected")
	default:
	}

	// The server drops every connection; messages published meanwhile are lost.
	srv.Close()
	if err := srv.Restart(); err != nil {
		t.Fatal(err)
	}

	dropped := time.Now()
	select {
	case <-gaps:
		t.Logf("gap reported %s after the drop", time.Since(dropped))
	case <-time.After(5 * time.Second):
		t.Fatal("the dropped connection was never reported as a gap")
	}
	publishUntilReceived("after")
}
