package ws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func originServer(t *testing.T, upgrade func(http.ResponseWriter, *http.Request) (*ServerConnection, error)) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if conn, err := upgrade(w, r); err == nil {
			conn.Close()
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func dialOrigin(url, origin string) (int, error) {
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	c, resp, err := websocket.DefaultDialer.Dial(url, h)
	if c != nil {
		c.Close()
	}
	if resp == nil {
		return 0, err
	}
	return resp.StatusCode, err
}

// NewServerConnection keeps accepting any origin: its callers that take
// browsers from other origins on token auth depend on it.
func TestNewServerConnection_anyOrigin(t *testing.T) {
	url := originServer(t, NewServerConnection)
	if status, err := dialOrigin(url, "https://evil.example"); err != nil {
		t.Fatalf("status %d: %v", status, err)
	}
}

// With a nil check a page on another origin is refused, a client that sends
// no Origin (every non-browser one) and a same-origin page are not.
func TestNewServerConnectionCheckOrigin_default(t *testing.T) {
	url := originServer(t, func(w http.ResponseWriter, r *http.Request) (*ServerConnection, error) {
		return NewServerConnectionCheckOrigin(w, r, nil)
	})
	if status, err := dialOrigin(url, "https://evil.example"); err == nil || status != http.StatusForbidden {
		t.Fatalf("cross-origin handshake: status %d, err %v; want 403", status, err)
	}
	if status, err := dialOrigin(url, ""); err != nil {
		t.Fatalf("no Origin: status %d: %v", status, err)
	}
	if status, err := dialOrigin(url, "http"+strings.TrimPrefix(url, "ws")); err != nil {
		t.Fatalf("same origin: status %d: %v", status, err)
	}
}

// The caller's check decides.
func TestNewServerConnectionCheckOrigin_custom(t *testing.T) {
	url := originServer(t, func(w http.ResponseWriter, r *http.Request) (*ServerConnection, error) {
		return NewServerConnectionCheckOrigin(w, r, func(r *http.Request) bool {
			return r.Header.Get("Origin") == "https://app.example"
		})
	})
	if status, err := dialOrigin(url, "https://app.example"); err != nil {
		t.Fatalf("allowed origin: status %d: %v", status, err)
	}
	if status, err := dialOrigin(url, "https://evil.example"); err == nil || status != http.StatusForbidden {
		t.Fatalf("other origin: status %d, err %v; want 403", status, err)
	}
}
