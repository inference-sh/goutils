package logging

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ArchiveFunc is called with the path of a compressed rotated log file.
type ArchiveFunc func(path string) error

// LogArchiver watches a log directory for new rotated .gz files
// and uploads them via the provided archive function.
type LogArchiver struct {
	dir     string
	fn      ArchiveFunc
	known   map[string]struct{}
	mu      sync.Mutex
	cancel  context.CancelFunc
	started bool
}

// NewLogArchiver creates an archiver for the given log directory.
// Call Start() to begin watching.
func NewLogArchiver(logDir string, fn ArchiveFunc) *LogArchiver {
	a := &LogArchiver{
		dir:   logDir,
		fn:    fn,
		known: make(map[string]struct{}),
	}

	// snapshot existing files so we don't re-upload old ones on startup
	if entries, err := os.ReadDir(logDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".gz") {
				a.known[e.Name()] = struct{}{}
			}
		}
	}

	return a
}

// Start begins the background scan loop. Safe to call once.
func (a *LogArchiver) Start(ctx context.Context) {
	a.mu.Lock()
	if a.started {
		a.mu.Unlock()
		return
	}
	a.started = true
	ctx, a.cancel = context.WithCancel(ctx)
	a.mu.Unlock()

	go a.loop(ctx)
}

// Stop cancels the background loop.
func (a *LogArchiver) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		a.cancel()
	}
}

func (a *LogArchiver) loop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.scan()
		}
	}
}

func (a *LogArchiver) scan() {
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		Error("archive").Err(err).Msg("failed to scan log directory")
		return
	}

	// collect current .gz files for pruning stale entries
	current := make(map[string]struct{}, len(entries))

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".gz") {
			continue
		}
		current[e.Name()] = struct{}{}

		a.mu.Lock()
		_, seen := a.known[e.Name()]
		a.mu.Unlock()

		if seen {
			continue
		}

		path := filepath.Join(a.dir, e.Name())
		if err := a.fn(path); err != nil {
			Error("archive").Err(err).Str("file", e.Name()).Msg("failed to archive rotated log")
			continue
		}

		Info("archive").Str("file", e.Name()).Msg("archived rotated log")

		a.mu.Lock()
		a.known[e.Name()] = struct{}{}
		a.mu.Unlock()
	}

	// prune entries for files that no longer exist on disk
	a.mu.Lock()
	for name := range a.known {
		if _, exists := current[name]; !exists {
			delete(a.known, name)
		}
	}
	a.mu.Unlock()
}

// ArchiveKey returns a storage key for a log file.
// Format: logs/{source}/{filename}
func ArchiveKey(source, filePath string) string {
	return fmt.Sprintf("logs/%s/%s", source, filepath.Base(filePath))
}
