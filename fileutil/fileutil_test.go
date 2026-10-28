package fileutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	for _, content := range []string{"one", "two"} {
		if err := WriteFileAtomic(path, strings.NewReader(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if b, err := ReadOwnFile(path); err != nil || string(b) != content {
			t.Fatalf("read back %q, %v; want %q", b, err, content)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestReadOwnFileMissing(t *testing.T) {
	if _, err := ReadOwnFile(filepath.Join(t.TempDir(), "none")); !os.IsNotExist(err) {
		t.Errorf("missing: %v, want not-exist", err)
	}
}
