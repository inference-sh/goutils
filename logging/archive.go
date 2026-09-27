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
	dir      string
	fn       ArchiveFunc
	known    map[string]struct{}
	failures map[string]int
	mu       sync.Mutex
	cancel   context.CancelFunc
	started  bool
}

// markerDir holds one empty file per uploaded log, named after it. It is how
// the archiver remembers across restarts what it already shipped: a file
// rotated just before a restart and not yet uploaded has no marker, so the
// next process uploads it instead of taking it for old news.
const markerDir = ".archived"

// NewLogArchiver creates an archiver for the given log directory.
// Call Start() to begin watching.
func NewLogArchiver(logDir string, fn ArchiveFunc) *LogArchiver {
	a := &LogArchiver{
		dir:      logDir,
		fn:       fn,
		known:    make(map[string]struct{}),
		failures: make(map[string]int),
	}

	if entries, err := os.ReadDir(filepath.Join(logDir, markerDir)); err == nil {
		for _, e := range entries {
			a.known[e.Name()] = struct{}{}
		}
	}

	return a
}

// markArchived records name as uploaded, in memory and on disk. A marker
// that can't be written only costs a duplicate upload after a restart.
func (a *LogArchiver) markArchived(name string) {
	a.known[name] = struct{}{}
	dir := filepath.Join(a.dir, markerDir)
	if err := os.MkdirAll(dir, 0o755); err == nil {
		_ = os.WriteFile(filepath.Join(dir, name), nil, 0o644)
	}
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

	// Catch up on anything a previous process rotated but never shipped.
	a.scan()

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
			a.mu.Lock()
			a.failures[e.Name()]++
			count := a.failures[e.Name()]
			if count >= 3 {
				// Given up for this process only: no marker, so the next
				// process tries again.
				a.known[e.Name()] = struct{}{}
				delete(a.failures, e.Name())
				a.mu.Unlock()
				Error("archive").Err(err).Str("file", e.Name()).Msg("giving up after 3 failures")
			} else {
				a.mu.Unlock()
				Error("archive").Err(err).Str("file", e.Name()).Int("attempt", count).Msg("failed to archive rotated log")
			}
			continue
		}

		Info("archive").Str("file", e.Name()).Msg("archived rotated log")

		a.mu.Lock()
		a.markArchived(e.Name())
		delete(a.failures, e.Name())
		a.mu.Unlock()
	}

	// prune entries for files that no longer exist on disk
	a.mu.Lock()
	for name := range a.known {
		if _, exists := current[name]; !exists {
			delete(a.known, name)
			_ = os.Remove(filepath.Join(a.dir, markerDir, name))
		}
	}
	for name := range a.failures {
		if _, exists := current[name]; !exists {
			delete(a.failures, name)
		}
	}
	a.mu.Unlock()
}

// ArchiveKey returns a storage key for a log file.
// Format: logs/{source}/{filename}, or logs/audit/{source}/{filename} for the
// audit log, so audit files can carry their own retention rule.
func ArchiveKey(source, filePath string) string {
	name := filepath.Base(filePath)
	if strings.HasPrefix(name, auditRotatedPrefix) {
		return fmt.Sprintf("logs/audit/%s/%s", source, name)
	}
	return fmt.Sprintf("logs/%s/%s", source, name)
}

// auditRotatedPrefix starts every rotated copy of AuditFilename.
var auditRotatedPrefix = strings.TrimSuffix(AuditFilename, filepath.Ext(AuditFilename)) + "-"
