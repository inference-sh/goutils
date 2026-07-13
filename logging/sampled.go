package logging

import (
	"sync"
	"time"
)

// Sampled gates log emission by key with a minimum interval.
// Use it to avoid flooding logs from hot paths while still
// emitting distinct warnings per key (e.g. per app_id).
//
//	var warn = logging.NewSampled(time.Minute)
//
//	if warn.Should("overcommitted") {
//	    logging.Warn("scheduler").Msg("pool over-committed")
//	}
type Sampled struct {
	interval time.Duration
	seen     sync.Map // key → time.Time
}

// NewSampled creates a sampled gate with the given minimum interval between
// emissions of the same key.
func NewSampled(interval time.Duration) *Sampled {
	return &Sampled{interval: interval}
}

// Should returns true if the key hasn't been emitted within the interval.
func (s *Sampled) Should(key string) bool {
	now := time.Now()
	if last, ok := s.seen.Load(key); ok {
		if now.Sub(last.(time.Time)) < s.interval {
			return false
		}
	}
	s.seen.Store(key, now)
	return true
}
