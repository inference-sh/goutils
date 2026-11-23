package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rs/zerolog"
)

// The audit rotator kept every hourly rotation for MaxAge days, and
// unauthenticated requests write audit lines, so the log volume had no bound
// below MaxAge days of attacker-driven volume (aikido 796590290).

func TestAuditRotator_keepsABoundedNumberOfBackups(t *testing.T) {
	if got := newAuditRotator(Config{Dir: t.TempDir(), MaxSize: 1, MaxAge: 90}).MaxBackups; got != DefaultAuditMaxBackups {
		t.Fatalf("default MaxBackups = %d, want %d", got, DefaultAuditMaxBackups)
	}

	dir := t.TempDir()
	f := newAuditRotator(Config{Dir: dir, MaxSize: 1, MaxAge: 90, AuditMaxBackups: 2})
	t.Cleanup(func() { _ = f.Close() })
	for i := 0; i < 6; i++ {
		if _, err := f.Write([]byte("audit line\n")); err != nil {
			t.Fatal(err)
		}
		if err := f.Rotate(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond) // rotated names carry a millisecond timestamp
	}

	// lumberjack removes old backups in the background.
	deadline := time.Now().Add(3 * time.Second)
	for {
		backups := 0
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), auditRotatedPrefix) {
				backups++
			}
		}
		if backups <= 2 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d rotated audit files on disk, want at most 2", backups)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAudit_capsCallerChosenFields(t *testing.T) {
	dir := t.TempDir()
	root := Root
	t.Cleanup(func() { Root = root; auditRoot = nil })
	if err := Init(Config{Dir: dir, Filename: "main.txt", MaxSize: 10, Level: zerolog.DebugLevel, Audit: true}); err != nil {
		t.Fatal(err)
	}

	longPath := "/" + strings.Repeat("p", 100_000)
	longUA := strings.Repeat("u", 100_000)
	Audit("auth.failed", "", "endpoint", longPath, "denied", &AuditContext{UserAgent: longUA})

	audit, err := os.ReadFile(filepath.Join(dir, AuditFilename))
	if err != nil {
		t.Fatal(err)
	}
	// target_id appears in the field and in the message: two copies at most.
	if len(audit) > 4*1024 {
		t.Fatalf("audit line is %d bytes; caller-chosen fields are not capped", len(audit))
	}
	if !strings.Contains(string(audit), "...[truncated]") {
		t.Fatalf("truncation is not marked: %.200q", audit)
	}
}

func TestTruncateField_keepsUTF8Valid(t *testing.T) {
	s := strings.Repeat("é", 100) // two bytes each
	got := truncateField(s, 51)
	if len(got) > 51 || !utf8.ValidString(got) || !strings.HasSuffix(got, "...[truncated]") {
		t.Fatalf("truncateField = %q (%d bytes)", got, len(got))
	}
	if truncateField("short", 51) != "short" {
		t.Fatal("short values must pass unchanged")
	}
}
