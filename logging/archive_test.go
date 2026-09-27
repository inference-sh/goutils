package logging

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
)

type uploads struct {
	mu    sync.Mutex
	names []string
}

func (u *uploads) fn(path string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.names = append(u.names, filepath.Base(path))
	return nil
}

func (u *uploads) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.names)
}

func writeGz(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A file rotated just before a restart must still be uploaded by the next
// process. The archiver used to mark every .gz present at startup as done.
func TestLogArchiver_uploadsFilesLeftByAPreviousProcess(t *testing.T) {
	dir := t.TempDir()
	writeGz(t, dir, "api-1.txt.gz")

	first := &uploads{}
	NewLogArchiver(dir, first.fn).scan()
	if first.count() != 1 {
		t.Fatalf("first process uploaded %d files, want 1", first.count())
	}

	writeGz(t, dir, "api-2.txt.gz") // rotated, then the process restarted

	second := &uploads{}
	NewLogArchiver(dir, second.fn).scan()
	if len(second.names) != 1 || second.names[0] != "api-2.txt.gz" {
		t.Fatalf("second process uploaded %v, want only api-2.txt.gz", second.names)
	}
}

func TestLogArchiver_prunesMarkersOfDeletedFiles(t *testing.T) {
	dir := t.TempDir()
	writeGz(t, dir, "api-1.txt.gz")
	a := NewLogArchiver(dir, (&uploads{}).fn)
	a.scan()

	if err := os.Remove(filepath.Join(dir, "api-1.txt.gz")); err != nil {
		t.Fatal(err)
	}
	a.scan()

	if _, err := os.Stat(filepath.Join(dir, markerDir, "api-1.txt.gz")); !os.IsNotExist(err) {
		t.Fatalf("marker for a deleted file still exists: %v", err)
	}
}

func TestArchiveKey_auditFilesHaveTheirOwnPrefix(t *testing.T) {
	if got := ArchiveKey("api/i1", "/logs/audit-2026-09-27T10-00-00.000.txt.gz"); got != "logs/audit/api/i1/audit-2026-09-27T10-00-00.000.txt.gz" {
		t.Fatalf("audit key = %s", got)
	}
	if got := ArchiveKey("api/i1", "/logs/inference-sh-api-2026.txt.gz"); got != "logs/api/i1/inference-sh-api-2026.txt.gz" {
		t.Fatalf("main key = %s", got)
	}
}

func TestAudit_writesToTheAuditFileToo(t *testing.T) {
	dir := t.TempDir()
	root := Root
	t.Cleanup(func() { Root = root; auditRoot = nil })

	if err := Init(Config{Dir: dir, Filename: "main.txt", MaxSize: 1, Level: zerolog.DebugLevel, Audit: true}); err != nil {
		t.Fatal(err)
	}
	Info("api").Msg("ordinary line")
	Audit("store.version.approved", "u1", "app_store_version", "v1", "success", nil)

	audit, err := os.ReadFile(filepath.Join(dir, AuditFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), "store.version.approved") || strings.Contains(string(audit), "ordinary line") {
		t.Fatalf("audit file = %q", audit)
	}
	main, err := os.ReadFile(filepath.Join(dir, "main.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(main), "store.version.approved") {
		t.Fatalf("audit event missing from the main log: %q", main)
	}
}
