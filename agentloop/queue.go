package agentloop

import "sync"

// QueueMode controls how many messages are drained at each injection point.
type QueueMode int

const (
	// QueueAll drains every queued message at once.
	QueueAll QueueMode = iota

	// QueueOneAtATime drains only the oldest message, leaving the rest
	// for later drain points.
	QueueOneAtATime
)

// messageQueue is a thread-safe FIFO queue for steering and follow-up messages.
type messageQueue struct {
	mu       sync.Mutex
	messages []Message
	mode     QueueMode
}

func newMessageQueue(mode QueueMode) *messageQueue {
	return &messageQueue{mode: mode}
}

func (q *messageQueue) Enqueue(msg Message) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.messages = append(q.messages, msg)
}

func (q *messageQueue) Drain() []Message {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.messages) == 0 {
		return nil
	}

	if q.mode == QueueAll {
		drained := q.messages
		q.messages = nil
		return drained
	}

	first := q.messages[0]
	q.messages[0] = Message{} // avoid pinning in underlying array
	q.messages = q.messages[1:]
	return []Message{first}
}

