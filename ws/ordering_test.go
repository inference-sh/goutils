package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// feed pushes messages through a connection's processing pipeline the way
// Listen does, without a socket.
func feed(t *testing.T, b *BaseConnection, msgs []RawMessage) {
	t.Helper()
	go b.processMessages()
	for _, m := range msgs {
		b.msgBuffer <- m
	}
}

func taskMsg(taskID string, n int) RawMessage {
	data, _ := json.Marshal(map[string]any{"task_id": taskID, "n": n})
	return RawMessage{Type: "task_output", Data: data}
}

// Messages about one task are handled in the order they were read, even when
// many tasks interleave on one connection. This is what keeps streamed text
// in order.
func TestMessagesForOneTaskAreHandledInOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := NewBaseConnection(ctx)

	const tasks, perTask = 8, 500
	var mu sync.Mutex
	seen := map[string][]int{}
	var wg sync.WaitGroup
	wg.Add(tasks * perTask)
	b.Handle("task_output", HandleFunc(func(_ context.Context, m Message[struct {
		TaskID string `json:"task_id"`
		N      int    `json:"n"`
	}]) {
		mu.Lock()
		seen[m.Data.TaskID] = append(seen[m.Data.TaskID], m.Data.N)
		mu.Unlock()
		wg.Done()
	}))

	var msgs []RawMessage
	for n := 0; n < perTask; n++ {
		for task := 0; task < tasks; task++ {
			msgs = append(msgs, taskMsg(fmt.Sprintf("task-%d", task), n))
		}
	}
	feed(t, &b, msgs)
	wg.Wait()

	for task, ns := range seen {
		for i, n := range ns {
			if n != i {
				t.Fatalf("%s: message %d handled at position %d (first 12: %v)", task, n, i, ns[:12])
			}
		}
	}
}

// Different tasks still run in parallel: a handler stuck on one task does not
// stop tasks in other lanes, and up to DefaultLanes handlers run at once.
func TestTasksInDifferentLanesRunInParallel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := NewBaseConnection(ctx)

	var running, peak atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup

	// One task per lane, found by probing keys until every lane has one.
	keys := map[int]string{}
	for i := 0; len(keys) < DefaultLanes; i++ {
		k := fmt.Sprintf("task-%d", i)
		if _, ok := keys[b.laneFor(taskMsg(k, 0))]; !ok {
			keys[b.laneFor(taskMsg(k, 0))] = k
		}
	}
	wg.Add(len(keys))
	b.Handle("task_output", HandleFunc(func(_ context.Context, _ Message[json.RawMessage]) {
		now := running.Add(1)
		for {
			p := peak.Load()
			if now <= p || peak.CompareAndSwap(p, now) {
				break
			}
		}
		<-release
		running.Add(-1)
		wg.Done()
	}))

	var msgs []RawMessage
	for _, k := range keys {
		msgs = append(msgs, taskMsg(k, 0))
	}
	feed(t, &b, msgs)

	deadline := time.Now().Add(2 * time.Second)
	for peak.Load() < int32(DefaultLanes) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	wg.Wait()
	if got := peak.Load(); got != int32(DefaultLanes) {
		t.Fatalf("peak concurrent handlers = %d, want %d", got, DefaultLanes)
	}
	t.Logf("%d handlers ran at once, one per lane", peak.Load())
}

// Messages without a task id fall back to worker_id, then to one shared lane.
func TestOrderingKeyFallsBack(t *testing.T) {
	cases := map[string]string{
		`{"task_id":"t1","worker_id":"w1"}`: "t1",
		`{"worker_id":"w1"}`:                "w1",
		`{"engine_id":"e1"}`:                "",
		``:                                  "",
	}
	for data, want := range cases {
		if got := DefaultOrderingKey(RawMessage{Type: "x", Data: json.RawMessage(data)}); got != want {
			t.Errorf("DefaultOrderingKey(%s) = %q, want %q", data, got, want)
		}
	}
}
