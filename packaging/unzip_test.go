package packaging

import (
	"archive/zip"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type zipEntry struct {
	name string
	mode os.FileMode
	body string
}

func link(name, target string) zipEntry { return zipEntry{name, os.ModeSymlink | 0o777, target} }
func file(name, body string) zipEntry   { return zipEntry{name, 0o644, body} }

func writeZip(t *testing.T, entries ...zipEntry) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pkg.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		h.SetMode(e.mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func unixOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix modes and symlinks")
	}
}

func TestExtractZip_StripsSpecialModeBits(t *testing.T) {
	unixOnly(t)
	dest := t.TempDir()
	zp := writeZip(t,
		zipEntry{"run.sh", 0o4777 | os.ModeSetuid, "#!/bin/sh"},
		zipEntry{"lib.py", 0o2666 | os.ModeSetgid, "x"},
		zipEntry{"ro.txt", 0o400, "x"},
	)
	if err := ExtractZip(zp, dest, ExtractOptions{}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{"run.sh": 0o755, "lib.py": 0o644, "ro.txt": 0o600} {
		info, err := os.Stat(filepath.Join(dest, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", name, info.Mode(), want)
		}
	}
}

func TestExtractZip_Limits(t *testing.T) {
	dest := t.TempDir()
	zp := writeZip(t, file("a", strings.Repeat("a", 600)), file("b", strings.Repeat("b", 600)))
	if err := ExtractZip(zp, dest, ExtractOptions{MaxBytes: 1000}); err == nil || !strings.Contains(err.Error(), "more than 1000 bytes") {
		t.Fatalf("err = %v, want the size cap", err)
	}
	if err := ExtractZip(zp, t.TempDir(), ExtractOptions{MaxEntries: 1}); err == nil || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("err = %v, want the entry cap", err)
	}
}

func TestExtractZip_RefusesTraversal(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "app")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ExtractZip(writeZip(t, file("../escape.py", "x")), dest, ExtractOptions{}); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := os.Stat(filepath.Join(base, "escape.py")); !os.IsNotExist(err) {
		t.Fatalf("entry written outside the destination: %v", err)
	}
}

func TestExtractZip_SkipsSymlinksByDefault(t *testing.T) {
	unixOnly(t)
	dest := t.TempDir()
	var skipped []string
	opt := ExtractOptions{OnSkip: func(name string, _ fs.FileMode) { skipped = append(skipped, name) }}
	if err := ExtractZip(writeZip(t, link("link", "/etc/passwd"), file("main.py", "print(1)")), dest, opt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "link")); !os.IsNotExist(err) {
		t.Fatalf("symlink entry extracted: %v", err)
	}
	if len(skipped) != 1 || skipped[0] != "link" {
		t.Fatalf("skipped = %v", skipped)
	}
}

func TestExtractZip_KeepsContainedSymlinks(t *testing.T) {
	unixOnly(t)
	dest := t.TempDir()
	zp := writeZip(t, file("lib/real.py", "x"), link("alias.py", "lib/real.py"))
	opt := ExtractOptions{KeepSymlinks: true}
	if err := ExtractZip(zp, dest, opt); err != nil {
		t.Fatal(err)
	}
	// Extracting again over the same tree replaces the link.
	if err := ExtractZip(zp, dest, opt); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(dest, "alias.py")); err != nil || target != "lib/real.py" {
		t.Fatalf("link = %q, %v", target, err)
	}
}

func TestExtractZip_RefusesEscapingSymlinks(t *testing.T) {
	unixOnly(t)
	cases := map[string][]zipEntry{
		"relative escape":         {link("inf.yml", "../outside.yml")},
		"absolute target":         {link("inf.yml", "/etc/passwd")},
		"chain through self-link": {link("d", "."), link("inf.yml", "d/d/d/../../../outside.yml")},
		"entry through symlink":   {link("d", ".."), link("d/outside.yml", "pwned")},
		"dangling":                {link("inf.yml", "nope")},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			dest := filepath.Join(base, "app")
			if err := os.Mkdir(dest, 0o755); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(base, "outside.yml")
			if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ExtractZip(writeZip(t, entries...), dest, ExtractOptions{KeepSymlinks: true}); err == nil {
				t.Fatal("expected an error")
			}
			if _, err := os.Lstat(filepath.Join(dest, "inf.yml")); !os.IsNotExist(err) {
				t.Fatal("escaping inf.yml link must not survive")
			}
			if got, _ := os.ReadFile(outside); string(got) != "keep" {
				t.Fatalf("outside file changed: %q", got)
			}
		})
	}
}

func TestExtractZip_LeavesExistingLinksInDest(t *testing.T) {
	unixOnly(t)
	dest := t.TempDir()
	// A preserved venv link the user already has must not be touched.
	if err := os.Symlink("/usr/bin/python3", filepath.Join(dest, "python")); err != nil {
		t.Fatal(err)
	}
	if err := ExtractZip(writeZip(t, file("main.py", "x")), dest, ExtractOptions{KeepSymlinks: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "python")); err != nil {
		t.Fatal(err)
	}
}
