package agentloop

import "testing"

func TestMessageQueue_DrainAll(t *testing.T) {
	q := newMessageQueue(QueueAll)

	q.Enqueue(TextMessage(RoleUser, "a"))
	q.Enqueue(TextMessage(RoleUser, "b"))
	q.Enqueue(TextMessage(RoleUser, "c"))

	drained := q.Drain()
	if len(drained) != 3 {
		t.Fatalf("expected 3, got %d", len(drained))
	}
	if drained[0].Text() != "a" || drained[1].Text() != "b" || drained[2].Text() != "c" {
		t.Error("unexpected drain order")
	}

	if drained := q.Drain(); drained != nil {
		t.Errorf("expected nil drain on empty queue, got %d items", len(drained))
	}
}

func TestMessageQueue_DrainOneAtATime(t *testing.T) {
	q := newMessageQueue(QueueOneAtATime)

	q.Enqueue(TextMessage(RoleUser, "a"))
	q.Enqueue(TextMessage(RoleUser, "b"))

	d1 := q.Drain()
	if len(d1) != 1 || d1[0].Text() != "a" {
		t.Errorf("expected [a], got %v", d1)
	}

	d2 := q.Drain()
	if len(d2) != 1 || d2[0].Text() != "b" {
		t.Errorf("expected [b], got %v", d2)
	}

	if d := q.Drain(); d != nil {
		t.Errorf("expected nil drain on empty queue, got %d items", len(d))
	}
}
