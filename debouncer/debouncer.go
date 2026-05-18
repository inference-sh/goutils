package debouncer

import (
	"context"
	"sync"
	"time"
)

type Debouncer struct {
	Delay, Force time.Duration
	mu           sync.Mutex
	entries      map[string]*debounceEntry
}

type debounceEntry struct {
	firstCall time.Time
	lastCall  time.Time
	cancel    context.CancelFunc
	callback  func()
	timer     *time.Timer
}

func NewDebouncer(delay, force time.Duration) *Debouncer {
	return &Debouncer{
		Delay:   delay,
		Force:   force,
		entries: make(map[string]*debounceEntry),
	}
}

func (d *Debouncer) Debounce(id string, callback func()) {
	now := time.Now()

	d.mu.Lock()
	if d.entries == nil {
		d.entries = make(map[string]*debounceEntry)
	}
	e, exists := d.entries[id]
	if exists {
		e.cancel()
		if e.timer != nil && !e.timer.Stop() {
			select {
			case <-e.timer.C:
			default:
			}
		}
	} else {
		e = &debounceEntry{firstCall: now}
		d.entries[id] = e
	}

	e.lastCall = now
	e.callback = callback

	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel

	trailing := e.lastCall.Add(d.Delay)
	maxWait := e.firstCall.Add(d.Force)
	execAt := trailing
	if maxWait.Before(trailing) {
		execAt = maxWait
	}
	delta := time.Until(execAt)

	timer := time.NewTimer(delta)
	e.timer = timer

	d.mu.Unlock()

	go func(ctx context.Context, id string, t *time.Timer) {
		select {
		case <-t.C:
			d.invoke(id)
		case <-ctx.Done():
			// canceled
		}
	}(ctx, id, timer)
}

func (d *Debouncer) invoke(id string) {
	d.mu.Lock()
	e, ok := d.entries[id]
	if !ok {
		d.mu.Unlock()
		return
	}
	delete(d.entries, id)
	cb := e.callback
	d.mu.Unlock()

	if cb != nil {
		cb()
	}
}

func (d *Debouncer) Clear(id string) {

	d.mu.Lock()
	defer d.mu.Unlock()

	if e, ok := d.entries[id]; ok {
		e.cancel()
		if e.timer != nil && !e.timer.Stop() {
			select {
			case <-e.timer.C:
			default:
			}
		}
		delete(d.entries, id)
	}
}
