package binresolve

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestNewRequiresFields verifies the constructor rejects missing required config.
func TestNewRequiresFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing manifest url", Config{BinaryName: "engine", CacheDir: "/tmp/x"}},
		{"missing binary name", Config{ManifestURL: "https://x/m.json", CacheDir: "/tmp/x"}},
		{"missing cache dir", Config{ManifestURL: "https://x/m.json", BinaryName: "engine"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestNewComputesPaths(t *testing.T) {
	tmp := t.TempDir()
	r, err := New(Config{
		ManifestURL: "https://x/m.json",
		BinaryName:  "engine",
		CacheDir:    tmp,
		Platform:    "linux",
		Arch:        "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantBin := filepath.Join(tmp, "bin", "engine")
	if r.BinaryPath() != wantBin {
		t.Errorf("BinaryPath = %s, want %s", r.BinaryPath(), wantBin)
	}
}

func TestNewWindowsAppendsExe(t *testing.T) {
	tmp := t.TempDir()
	r, err := New(Config{
		ManifestURL: "https://x/m.json",
		BinaryName:  "engine",
		CacheDir:    tmp,
		Platform:    "windows",
		Arch:        "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantBin := filepath.Join(tmp, "bin", "engine.exe")
	if r.BinaryPath() != wantBin {
		t.Errorf("BinaryPath = %s, want %s", r.BinaryPath(), wantBin)
	}
}

// TestEnsureEndToEnd stands up a fake dist.inference.sh with a manifest and a
// tar.gz archive, points the resolver at it, and verifies Ensure downloads
// the binary correctly.
func TestEnsureEndToEnd(t *testing.T) {
	payload := []byte("fake engine binary content")
	archive := makeTarGz(t, "engine", payload)
	archiveSHA := sha256Hex(archive)

	var manifestURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/engine/test-v1.0.0.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(archive)))
		w.Write(archive)
	})
	mux.HandleFunc("/engine/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		m := map[string]any{
			"version":     "v1.0.0",
			"releaseDate": time.Now().Format(time.RFC3339),
			"builds": map[string]any{
				fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH): map[string]any{
					"url":        manifestURL + "/engine/test-v1.0.0.tar.gz",
					"binaryName": "test-v1.0.0.tar.gz",
					"sha256":     archiveSHA,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(m)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	manifestURL = srv.URL

	tmp := t.TempDir()
	r, err := New(Config{
		ManifestURL: srv.URL + "/engine/manifest.json",
		BinaryName:  "engine",
		CacheDir:    tmp,
	})
	if err != nil {
		t.Fatal(err)
	}

	// First call: downloads.
	path, err := r.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch:\nwant %q\ngot  %q", payload, got)
	}

	// Second call: should short-circuit on cache (no error, same path).
	// The "fake binary" can't actually report its version, so cachedVersion()
	// returns "v0.0.0" and the manifest still says v1.0.0 → resolver
	// re-downloads. This is the correct behaviour: a binary that can't
	// self-report is treated as "out of date" and refreshed.
	path2, err := r.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure (cached): %v", err)
	}
	if path2 != path {
		t.Errorf("cached path diverged: %s vs %s", path2, path)
	}
}

// TestCachedVersionRunsBinary verifies the resolver actually invokes
// `<binary> version --short` when reading the cached version, instead of
// reading a sidecar file.
func TestCachedVersionRunsBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script binary not portable to windows")
	}

	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A "binary" that prints v9.9.9 when called with `version --short`.
	scriptPath := filepath.Join(binDir, "engine")
	script := "#!/bin/sh\nif [ \"$1\" = \"version\" ] && [ \"$2\" = \"--short\" ]; then echo v9.9.9; fi\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	r, err := New(Config{
		ManifestURL: "https://example.invalid/manifest.json",
		BinaryName:  "engine",
		CacheDir:    tmp,
	})
	if err != nil {
		t.Fatal(err)
	}

	got := r.cachedVersion()
	if got != "v9.9.9" {
		t.Errorf("cachedVersion = %q, want v9.9.9", got)
	}

	// Second call should hit the in-memory cache.
	got2 := r.cachedVersion()
	if got2 != "v9.9.9" {
		t.Errorf("cachedVersion (memoised) = %q, want v9.9.9", got2)
	}
}

// TestCachedVersionMissingBinary returns v0.0.0 when the cache is empty.
func TestCachedVersionMissingBinary(t *testing.T) {
	tmp := t.TempDir()
	r, err := New(Config{
		ManifestURL: "https://example.invalid/manifest.json",
		BinaryName:  "engine",
		CacheDir:    tmp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := r.cachedVersion(); v != "v0.0.0" {
		t.Errorf("missing binary should report v0.0.0, got %q", v)
	}
}

// Helpers (copied from binfetch_test — tiny enough to duplicate).

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func makeTarGz(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o755,
		Size:     int64(len(payload)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar write header: %v", err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatalf("tar write body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	return buf.Bytes()
}
