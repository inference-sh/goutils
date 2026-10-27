package autoupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// releaseServer publishes version with a tar.gz build of payload for every
// platform key the tests use, and returns the manifest URL.
func releaseServer(t *testing.T, version string, payload []byte) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "belt", Mode: 0o755, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	archive := buf.Bytes()
	sum := sha256.Sum256(archive)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	build := map[string]string{"url": srv.URL + "/belt.tar.gz", "sha256": hex.EncodeToString(sum[:])}
	manifest, err := json.Marshal(map[string]any{
		"version": version,
		"builds":  map[string]any{"linux-amd64": build},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(manifest) })
	mux.HandleFunc("/belt.tar.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) })
	return srv.URL + "/manifest.json"
}

// planConfig is a Config for a binary at self, checking manifestURL as
// linux/amd64 whatever the host is.
func planConfig(manifestURL, version, self string) Config {
	return Config{
		ManifestURL:    manifestURL,
		CurrentVersion: version,
		Platform:       "linux",
		Arch:           "amd64",
		SelfPath:       self,
	}
}

func writeSelf(t *testing.T, dir string) string {
	t.Helper()
	self := filepath.Join(dir, "belt")
	if err := os.WriteFile(self, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	return self
}

func TestPrepareThenInstall(t *testing.T) {
	url := releaseServer(t, "v1.1.0", []byte("new"))
	self := writeSelf(t, t.TempDir())

	p, err := Prepare(planConfig(url, "v1.0.0", self))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	// The temp dir may sit behind a link (/var is /private/var on macOS) or
	// a short name (RUNNER~1 on Windows); SelfPath is the resolved file.
	real, err := filepath.EvalSymlinks(self)
	if err != nil {
		t.Fatal(err)
	}
	if !p.UpdateAvailable || p.From != "v1.0.0" || p.To != "v1.1.0" || p.SelfPath != real {
		t.Fatalf("plan = %+v, want SelfPath %s", p, real)
	}
	if b, _ := os.ReadFile(self); string(b) != "old" {
		t.Fatal("Prepare must not install")
	}
	if err := p.Install(t.Context()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if b, _ := os.ReadFile(self); string(b) != "new" {
		t.Fatalf("binary is %q after Install, want the release", b)
	}
}

func TestPrepareCurrent(t *testing.T) {
	url := releaseServer(t, "v1.0.0", []byte("same"))
	self := writeSelf(t, t.TempDir())

	p, err := Prepare(planConfig(url, "v1.0.0", self))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if p.UpdateAvailable || p.To != "v1.0.0" {
		t.Fatalf("plan = %+v, want current", p)
	}
	if err := p.Install(t.Context()); err != nil {
		t.Fatalf("Install of a current plan: %v", err)
	}
	if b, _ := os.ReadFile(self); string(b) != "old" {
		t.Fatal("a current plan must not touch the binary")
	}
}

func TestPrepareRefusals(t *testing.T) {
	url := releaseServer(t, "v1.1.0", []byte("new"))

	t.Run("dev build", func(t *testing.T) {
		_, err := Prepare(planConfig(url, "dev", writeSelf(t, t.TempDir())))
		if !errors.Is(err, ErrDevBuild) {
			t.Fatalf("err = %v, want ErrDevBuild", err)
		}
	})

	t.Run("package manager", func(t *testing.T) {
		_, err := Prepare(planConfig(url, "v1.0.0", "/opt/homebrew/Cellar/belt/1.0.0/bin/belt"))
		var managed *ErrManaged
		if !errors.As(err, &managed) || managed.Cmd != "brew upgrade belt" {
			t.Fatalf("err = %v, want ErrManaged with the brew command", err)
		}
	})

	t.Run("directory not writable", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("directory permissions do not stop file creation on Windows")
		}
		if os.Geteuid() == 0 {
			t.Skip("root can write anywhere")
		}
		dir := t.TempDir()
		self := writeSelf(t, dir)
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		_, err := Prepare(planConfig(url, "v1.0.0", self))
		var nw *ErrNotWritable
		if !errors.As(err, &nw) {
			t.Fatalf("err = %v, want ErrNotWritable", err)
		}
	})

	t.Run("not writable but current", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs directory permissions that stop writes")
		}
		dir := t.TempDir()
		self := writeSelf(t, dir)
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		p, err := Prepare(planConfig(url, "v1.1.0", self))
		if err != nil || p.UpdateAvailable {
			t.Fatalf("plan = %+v, err = %v; a current binary has nothing to write", p, err)
		}
	})

	t.Run("manifest unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		srv.Close()
		_, err := Prepare(planConfig(srv.URL+"/manifest.json", "v1.0.0", writeSelf(t, t.TempDir())))
		var managed *ErrManaged
		var nw *ErrNotWritable
		if err == nil || errors.Is(err, ErrDevBuild) || errors.As(err, &managed) || errors.As(err, &nw) {
			t.Fatalf("err = %v, want a manifest error", err)
		}
	})
}

// A package manager's link elsewhere on PATH still reads as the manager's.
func TestPackageManagerUpdateCmdFollowsLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	cellar := filepath.Join(root, "Cellar", "belt", "1.0.0", "bin")
	if err := os.MkdirAll(cellar, 0o755); err != nil {
		t.Fatal(err)
	}
	real := writeSelf(t, cellar)
	link := filepath.Join(root, "belt")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if got := PackageManagerUpdateCmd(link, "belt"); got != "brew upgrade belt" {
		t.Fatalf("PackageManagerUpdateCmd(link) = %q, want the brew command", got)
	}
}

// With Exact, a manifest naming an older build plans it; without, the
// binary is current.
func TestPrepareExact(t *testing.T) {
	url := releaseServer(t, "v1.0.0", []byte("older"))
	self := writeSelf(t, t.TempDir())

	cfg := planConfig(url, "v1.1.0-canary.1", self)
	p, err := Prepare(cfg)
	if err != nil || p.UpdateAvailable {
		t.Fatalf("plan = %+v, err = %v; an older release is not an update", p, err)
	}

	cfg.Exact = true
	p, err = Prepare(cfg)
	if err != nil || !p.UpdateAvailable || p.To != "v1.0.0" {
		t.Fatalf("plan = %+v, err = %v; want v1.0.0 planned", p, err)
	}
	if err := p.Install(t.Context()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(self); string(b) != "older" {
		t.Fatalf("binary is %q, want the named release", b)
	}

	p, err = Prepare(planConfig(url, "v1.0.0", self))
	if err != nil || p.UpdateAvailable {
		t.Fatalf("plan = %+v, err = %v; the named release is running", p, err)
	}
}

// The update command names the binary's package: Config.Package, or the
// file name without its extension.
func TestPrepareManagedNamesPackage(t *testing.T) {
	url := releaseServer(t, "v1.1.0", []byte("new"))
	cfg := planConfig(url, "v1.0.0", `/opt/homebrew/Cellar/engine/1.0.0/bin/engine`)
	var managed *ErrManaged
	if _, err := Prepare(cfg); !errors.As(err, &managed) || managed.Cmd != "brew upgrade engine" {
		t.Fatalf("err = %v, want 'brew upgrade engine'", err)
	}
	cfg.SelfPath = `/home/u/scoop/apps/belt/current/inferencesh.exe`
	cfg.Package = "belt"
	if _, err := Prepare(cfg); !errors.As(err, &managed) || managed.Cmd != "scoop update belt" {
		t.Fatalf("err = %v, want 'scoop update belt'", err)
	}
}
