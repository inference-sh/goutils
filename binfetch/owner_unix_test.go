//go:build !windows

package binfetch

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// An update replaces the binary with a new file, 0755, owned by whoever
// runs it: an existing binary's owner and looser mode do not carry over.
// As root (run the tests as root to cover it) a uid-1000 binary is left
// root-owned, as a root service that updates itself needs.
func TestDownloadAndInstallBinary_NewFileOwnedByUpdater(t *testing.T) {
	archive := makeTarGz(t, "engine", binaryPayload)
	url, srv := startArchiveServer(t, archive, ".tar.gz")
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "engine")
	if err := os.WriteFile(dest, []byte("old"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dest, 0o777); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dest, 1000, 1000); err != nil {
			t.Fatal(err)
		}
	}
	before := stat(t, dest)

	if err := DownloadAndInstallBinary(context.Background(), BinFetchOptions{
		URL: url, ExpectedSHA256: sha256Hex(archive), DestPath: dest,
	}); err != nil {
		t.Fatalf("install: %v", err)
	}
	after := stat(t, dest)
	if after.Ino == before.Ino {
		t.Error("the binary was changed in place, want a new file")
	}
	if int(after.Uid) != os.Geteuid() || int(after.Gid) != os.Getegid() {
		t.Errorf("binary owned by %d:%d, want the updater's %d:%d", after.Uid, after.Gid, os.Geteuid(), os.Getegid())
	}
	if mode := after.Mode & 0o7777; mode != 0o755 {
		t.Errorf("binary mode %04o, want 0755", mode)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("want only the binary left in %s, got %d entries", dir, len(entries))
	}
}

// A manifest's alias is a file name beside the binary, never a path.
func TestDownloadAndInstallBinary_RefusesPathAlias(t *testing.T) {
	archive := makeTarGz(t, "inferencesh", binaryPayload)
	url, srv := startArchiveServer(t, archive, ".tar.gz")
	defer srv.Close()

	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"../victim", "..", ".hidden", "a/b"} {
		err := DownloadAndInstallBinary(context.Background(), BinFetchOptions{
			URL: url, ExpectedSHA256: sha256Hex(archive), DestPath: filepath.Join(bin, "inferencesh"),
			Aliases: []string{alias},
		})
		if err == nil {
			t.Errorf("alias %q: want an error", alias)
		}
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "keep" {
		t.Errorf("victim changed: %q, %v", b, err)
	}
}

func stat(t *testing.T, p string) *syscall.Stat_t {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t)
}
