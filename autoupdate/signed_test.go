package autoupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/inference-sh/goutils/updater"
)

func quietWarnings(t *testing.T) *int {
	n := 0
	prev := updater.Warnf
	updater.Warnf = func(string, ...any) { n++ }
	t.Cleanup(func() { updater.Warnf = prev })
	return &n
}

func requireCLISignature(t *testing.T) {
	prev := updater.Products["cli"]
	p := prev
	p.Required = true
	updater.Products["cli"] = p
	t.Cleanup(func() { updater.Products["cli"] = prev })
}

// The finding this guards: whoever controls the manifest's host chose the
// binary, since the manifest carried both the URL and the digest. A
// manifest whose bundle does not verify is refused before anything is
// downloaded.
func TestCheckAndReexecRefusesManifestWithBadBundle(t *testing.T) {
	evil := []byte("not the release")
	evilSum := sha256.Sum256(evil)
	downloaded := false

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	manifest, _ := json.Marshal(map[string]any{
		"product": "cli",
		"version": "v1.1.0",
		"builds":  map[string]any{"linux-amd64": map[string]string{"url": srv.URL + "/evil.tar.gz", "sha256": hex.EncodeToString(evilSum[:])}},
	})
	mux.HandleFunc("/cli/manifest.json", func(w http.ResponseWriter, _ *http.Request) { w.Write(manifest) })
	mux.HandleFunc("/cli/manifest.json"+updater.BundleSuffix, func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("{}")) })
	mux.HandleFunc("/evil.tar.gz", func(w http.ResponseWriter, _ *http.Request) { downloaded = true; w.Write(evil) })

	self := writeSelf(t, t.TempDir())
	cfg := planConfig(srv.URL+"/cli/manifest.json", "v1.0.0", self)
	cfg.StateDir = t.TempDir()
	cfg.execFn = func(string, []string) error { t.Fatal("re-exec after a refused manifest"); return nil }

	if _, err := CheckAndReexec(t.Context(), cfg); !errors.Is(err, updater.ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
	if _, err := Prepare(cfg); !errors.Is(err, updater.ErrBadSignature) {
		t.Fatalf("Prepare err = %v, want ErrBadSignature", err)
	}
	if downloaded {
		t.Fatal("downloaded the archive a refused manifest named")
	}
	if b, _ := os.ReadFile(self); string(b) != "old" {
		t.Fatalf("binary is %q, want it untouched", b)
	}
}

// Phase 1: a manifest published before signing (no bundle, no product) still
// installs, with a warning. This is a new binary moving to, or pinned at, an
// old release.
func TestUnsignedManifestStillInstallsInPhase1(t *testing.T) {
	warns := quietWarnings(t)
	url := releaseServerAt(t, "/cli/manifest.json", "v1.1.0", []byte("new"))
	self := writeSelf(t, t.TempDir())
	p, err := Prepare(planConfig(url, "v1.0.0", self))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := p.Install(t.Context()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if b, _ := os.ReadFile(self); string(b) != "new" {
		t.Fatalf("binary is %q, want the update", b)
	}
	if *warns != 1 {
		t.Fatalf("warnings = %d, want 1", *warns)
	}
}

// Once a product requires signatures, a cached download recorded from an
// unsigned manifest is not installed: the manifest is read again, and
// refused.
func TestRequiredIgnoresUnsignedCachedDownload(t *testing.T) {
	requireCLISignature(t)
	url := releaseServerAt(t, "/cli/manifest.json", "v1.1.0", []byte("new"))
	tmp := t.TempDir()
	self := writeSelf(t, tmp)
	cfg := planConfig(url, "v1.0.0", self)
	cfg.StateDir = t.TempDir()
	cfg.CheckInterval = time.Hour
	cfg.execFn = func(string, []string) error { t.Fatal("installed an unsigned cached download"); return nil }
	applyDefaults(&cfg)
	if err := writeState(stateFile(cfg), &state{
		LastCheck:   time.Now().Add(-time.Minute),
		LastVersion: "v1.1.0",
		DownloadURL: strings.TrimSuffix(url, "/cli/manifest.json") + "/belt.tar.gz",
		SHA256:      "00",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckAndReexec(t.Context(), cfg); !errors.Is(err, updater.ErrUnsigned) {
		t.Fatalf("err = %v, want ErrUnsigned from a fresh manifest read", err)
	}
}
