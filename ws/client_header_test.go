package ws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A client whose credential is replaced while it is disconnected sends the
// new one on its next attempt. With a fixed header it sent the old one
// forever and never came back.
func TestClientConnection_headerFuncIsAskedOnEveryDial(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		http.Error(w, "refused", http.StatusServiceUnavailable)
	}))
	t.Cleanup(s.Close)

	var calls atomic.Int32
	opts := DefaultClientOptions()
	opts.HandshakeTimeout = 200 * time.Millisecond
	opts.RecIntvlMin = 20 * time.Millisecond
	opts.RecIntvlMax = 40 * time.Millisecond
	opts.HeaderFunc = func() http.Header {
		token := "stale"
		if calls.Add(1) > 1 {
			token = "fresh"
		}
		return http.Header{"Authorization": {"Bearer " + token}}
	}
	c, err := NewClientConnectionWithOptions("ws"+strings.TrimPrefix(s.URL, "http"), opts)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 2 || seen[0] != "Bearer stale" || seen[1] != "Bearer fresh" {
		t.Fatalf("expected the stale then the fresh credential, got %q", seen)
	}
}
