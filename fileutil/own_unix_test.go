//go:build unix

package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReadOwnFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadOwnFile(path); err != nil || string(b) != "{}" {
		t.Fatalf("own file: %q, %v", b, err)
	}
	for _, m := range []os.FileMode{0o664, 0o666, 0o646} {
		if err := os.Chmod(path, m); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadOwnFile(path); !errors.Is(err, ErrNotOwn) {
			t.Errorf("mode %04o: %v, want ErrNotOwn", m, err)
		}
	}
	if _, err := ReadOwnFile(filepath.Dir(path)); !errors.Is(err, ErrNotOwn) {
		t.Errorf("directory: %v, want ErrNotOwn", err)
	}
	if os.Geteuid() == 0 {
		os.Chmod(path, 0o644)
		if err := os.Chown(path, 1000, 1000); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadOwnFile(path); !errors.Is(err, ErrNotOwn) {
			t.Errorf("uid 1000's file read by root: %v, want ErrNotOwn", err)
		}
	}
}

// A link at path is replaced, never written through, and the mode is the
// one asked for, not the old file's.
func TestWriteFileAtomicReplacesLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o666); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, strings.NewReader("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("wrote through the link: %q", b)
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
		t.Errorf("not a 0644 regular file: %v, %v", fi, err)
	}
}

// The owner is set before the file is in place; anyone may give a file to
// themselves, so this runs without root.
func TestWriteFileAtomicOwned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine")
	uid, gid := os.Getuid(), os.Getgid()
	if err := WriteFileAtomicOwned(path, strings.NewReader("x"), 0o755, uid, gid); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if int(st.Uid) != uid || int(st.Gid) != gid || fi.Mode().Perm() != 0o755 {
		t.Errorf("owner %d:%d mode %v", st.Uid, st.Gid, fi.Mode())
	}
}
