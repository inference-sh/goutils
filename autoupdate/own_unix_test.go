//go:build !windows

package autoupdate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A state file others can write is not read: it names the build an update
// installs without reading the manifest.
func TestStateWritableByOthersIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	if err := writeState(path, &state{LastCheck: time.Now(), LastVersion: "v9.9.9", DownloadURL: "https://evil.example/x.tar.gz"}); err != nil {
		t.Fatal(err)
	}
	if s, err := readState(path); err != nil || s == nil {
		t.Fatalf("own state: %v, %v", s, err)
	}
	for _, mode := range []os.FileMode{0o666, 0o664, 0o646} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if s, err := readState(path); err != nil || s != nil {
			t.Errorf("mode %04o: got %+v, %v; want ignored", mode, s, err)
		}
	}
	if os.Geteuid() == 0 {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 1000, 1000); err != nil {
			t.Fatal(err)
		}
		if s, _ := readState(path); s != nil {
			t.Error("a uid-1000 state file read by root, want ignored")
		}
	}
}

// writeState replaces a link at its path, never writes through it.
func TestWriteStateReplacesLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writeState(path, &state{LastCheck: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("wrote through the link: %q", b)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("state is not a regular file: %v, %v", fi, err)
	}
}
