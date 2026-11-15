package autoupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/inference-sh/goutils/updater"
)

// The finding this guards: whoever controls the manifest's host chose the
// binary, since the manifest carried both the URL and the digest. With a
// trusted key, a manifest rewritten to point at another archive (and that
// archive's real digest) is refused before anything is downloaded.
func TestCheckAndReexecRefusesTamperedSignedManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := updater.SetTrustedKeys(updater.EncodePublicKey(pub)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = updater.SetTrustedKeys() })

	evil := []byte("not the release")
	evilSum := sha256.Sum256(evil)
	downloaded := false

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	manifest := func(url, sha string) []byte {
		b, _ := json.Marshal(map[string]any{
			"product": "cli",
			"version": "v1.1.0",
			"builds":  map[string]any{"linux-amd64": map[string]string{"url": url, "sha256": sha}},
		})
		return b
	}
	genuine := manifest(srv.URL+"/cli/v1.1.0/belt.tar.gz", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tampered := manifest(srv.URL+"/evil.tar.gz", hex.EncodeToString(evilSum[:]))
	mux.HandleFunc("/cli/manifest.json", func(w http.ResponseWriter, _ *http.Request) { w.Write(tampered) })
	mux.HandleFunc("/cli/manifest.json.sig", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(updater.SignManifest(priv, genuine)))
	})
	mux.HandleFunc("/evil.tar.gz", func(w http.ResponseWriter, _ *http.Request) { downloaded = true; w.Write(evil) })

	self := writeSelf(t, t.TempDir())
	cfg := planConfig(srv.URL+"/cli/manifest.json", "v1.0.0", self)
	cfg.StateDir = t.TempDir()
	cfg.execFn = func(string, []string) error { t.Fatal("re-exec after a refused manifest"); return nil }

	_, err = CheckAndReexec(t.Context(), cfg)
	if !errors.Is(err, updater.ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
	if _, err := Prepare(cfg); !errors.Is(err, updater.ErrBadSignature) {
		t.Fatalf("Prepare err = %v, want ErrBadSignature", err)
	}
	if downloaded {
		t.Fatal("downloaded the archive a tampered manifest named")
	}
	if b, _ := os.ReadFile(self); string(b) != "old" {
		t.Fatalf("binary is %q, want it untouched", b)
	}
}
