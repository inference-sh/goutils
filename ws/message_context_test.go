package ws

import (
	"context"
	"sync"
	"testing"
)

type perMessageKey struct{}

// Each message is handled with its own context, built from the
// connection's: a value set for one message never reaches the next, and
// the connection's values still do.
func TestSetMessageContext_eachMessageGetsItsOwn(t *testing.T) {
	type connKey struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), connKey{}, "conn"))
	defer cancel()
	b := NewBaseConnection(ctx)
	b.SetMessageContext(func(ctx context.Context) context.Context {
		return context.WithValue(ctx, perMessageKey{}, new(int))
	})

	var mu sync.Mutex
	var seen []*int
	var wg sync.WaitGroup
	const n = 5
	wg.Add(n)
	b.Handle("task_output", HandleFunc(func(ctx context.Context, _ Message[struct{}]) {
		defer wg.Done()
		if ctx.Value(connKey{}) != "conn" {
			t.Error("the connection's values reach the handler")
		}
		mu.Lock()
		seen = append(seen, ctx.Value(perMessageKey{}).(*int))
		mu.Unlock()
	}))
	msgs := make([]RawMessage, n)
	for i := range msgs {
		msgs[i] = taskMsg("task-1", i)
	}
	feed(t, &b, msgs)
	wg.Wait()

	for i := range seen {
		for j := range i {
			if seen[i] == seen[j] {
				t.Fatalf("messages %d and %d shared a context value", j, i)
			}
		}
	}
}

// Without SetMessageContext a handler gets the connection's context.
func TestMessageContext_defaultsToTheConnections(t *testing.T) {
	type connKey struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), connKey{}, "conn"))
	defer cancel()
	b := NewBaseConnection(ctx)
	done := make(chan context.Context, 1)
	b.Handle("task_output", HandleFunc(func(ctx context.Context, _ Message[struct{}]) { done <- ctx }))
	feed(t, &b, []RawMessage{taskMsg("task-1", 0)})
	if got := <-done; got.Value(connKey{}) != "conn" {
		t.Error("the handler gets the connection's context")
	}
}
