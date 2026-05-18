package timeutil

import "time"

// Now returns the current time in UTC.
// Use this instead of time.Now() to ensure consistent timezone handling across the codebase.
func Now() time.Time {
	return time.Now().UTC()
}
