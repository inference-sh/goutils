package updater

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type keypair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newKey(t *testing.T) keypair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keypair{pub, priv}
}

func manifestBytes(t *testing.T, product, version, url, sha string) []byte {
	t.Helper()
	m := map[string]any{
		"product":     product,
		"version":     version,
		"releaseDate": "2026-11-15T00:00:00Z",
		"builds": map[string]any{
			"linux-amd64": map[string]string{"url": url, "binaryName": "x.tar.gz", "sha256": sha},
		},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// dist serves files by path; a missing path is a 404.
type dist struct {
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
}

func newDist(t *testing.T) (*dist, *httptest.Server) {
	d := &dist{files: map[string][]byte{}, hits: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.hits[r.URL.Path]++
		b, ok := d.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return d, srv
}

func (d *dist) put(path string, b []byte) {
	d.mu.Lock()
	d.files[path] = b
	d.mu.Unlock()
}

// withPolicy sets the trusted keys and phase for one test.
func withPolicy(t *testing.T, require bool, keys ...ed25519.PublicKey) *[]string {
	t.Helper()
	enc := make([]string, len(keys))
	for i, k := range keys {
		enc[i] = EncodePublicKey(k)
	}
	if err := SetTrustedKeys(enc...); err != nil {
		t.Fatal(err)
	}
	prevReq, prevWarn := RequireSignature, Warnf
	RequireSignature = require
	var warnings []string
	Warnf = func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }
	t.Cleanup(func() {
		RequireSignature, Warnf = prevReq, prevWarn
		_ = SetTrustedKeys()
	})
	return &warnings
}

const goodSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestCheckVersionSigned(t *testing.T) {
	k := newKey(t)
	d, srv := newDist(t)
	m := manifestBytes(t, "cli", "v1.2.0", srv.URL+"/cli/v1.2.0/x.tar.gz", goodSHA)
	d.put("/cli/manifest.json", m)
	d.put("/cli/manifest.json.sig", []byte(SignManifest(k.priv, m)))

	for _, require := range []bool{false, true} {
		t.Run(fmt.Sprintf("require=%v", require), func(t *testing.T) {
			warnings := withPolicy(t, require, k.pub)
			info, err := CheckVersion(srv.URL+"/cli/manifest.json", "linux", "amd64", "v1.1.0")
			if err != nil {
				t.Fatal(err)
			}
			if !info.Signed || info.SHA256 != goodSHA || !info.UpdateAvailable {
				t.Fatalf("info = %+v", info)
			}
			if len(*warnings) != 0 {
				t.Fatalf("warnings = %v", *warnings)
			}
		})
	}
}

func TestCheckVersionTamperedField(t *testing.T) {
	k := newKey(t)
	d, srv := newDist(t)
	m := manifestBytes(t, "cli", "v1.2.0", srv.URL+"/cli/v1.2.0/x.tar.gz", goodSHA)
	sig := []byte(SignManifest(k.priv, m))

	tampered := map[string][]byte{
		"url":     bytes.Replace(m, []byte(srv.URL+"/cli/"), []byte("https://evil.example/cli/"), 1),
		"sha256":  bytes.Replace(m, []byte(goodSHA), []byte(strings.Repeat("b", 64)), 1),
		"version": bytes.Replace(m, []byte("v1.2.0\""), []byte("v9.9.9\""), 1),
	}
	for name, body := range tampered {
		if bytes.Equal(body, m) {
			t.Fatalf("%s: tamper did not change the manifest", name)
		}
		for _, require := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/require=%v", name, require), func(t *testing.T) {
				withPolicy(t, require, k.pub)
				d.put("/cli/manifest.json", body)
				d.put("/cli/manifest.json.sig", sig)
				_, err := CheckVersion(srv.URL+"/cli/manifest.json", "linux", "amd64", "v1.1.0")
				if !errors.Is(err, ErrBadSignature) {
					t.Fatalf("err = %v, want ErrBadSignature", err)
				}
			})
		}
	}
}

func TestCheckVersionWrongKey(t *testing.T) {
	trusted, other := newKey(t), newKey(t)
	d, srv := newDist(t)
	m := manifestBytes(t, "cli", "v1.2.0", srv.URL+"/x.tar.gz", goodSHA)
	d.put("/cli/manifest.json", m)
	d.put("/cli/manifest.json.sig", []byte(SignManifest(other.priv, m)))

	for _, require := range []bool{false, true} {
		t.Run(fmt.Sprintf("require=%v", require), func(t *testing.T) {
			withPolicy(t, require, trusted.pub)
			_, err := CheckVersion(srv.URL+"/cli/manifest.json", "linux", "amd64", "v1.1.0")
			if !errors.Is(err, ErrBadSignature) {
				t.Fatalf("err = %v, want ErrBadSignature", err)
			}
		})
	}
}

func TestCheckVersionMissingSignature(t *testing.T) {
	k := newKey(t)
	d, srv := newDist(t)
	m := manifestBytes(t, "cli", "v1.2.0", srv.URL+"/x.tar.gz", goodSHA)
	d.put("/cli/manifest.json", m)

	t.Run("phase1 accepts with a warning", func(t *testing.T) {
		warnings := withPolicy(t, false, k.pub)
		info, err := CheckVersion(srv.URL+"/cli/manifest.json", "linux", "amd64", "v1.1.0")
		if err != nil {
			t.Fatal(err)
		}
		if info.Signed {
			t.Fatal("Signed = true for an unsigned manifest")
		}
		if len(*warnings) != 1 || !strings.Contains((*warnings)[0], "not signed") {
			t.Fatalf("warnings = %v", *warnings)
		}
	})
	t.Run("phase2 refuses", func(t *testing.T) {
		withPolicy(t, true, k.pub)
		_, err := CheckVersion(srv.URL+"/cli/manifest.json", "linux", "amd64", "v1.1.0")
		if !errors.Is(err, ErrUnsigned) {
			t.Fatalf("err = %v, want ErrUnsigned", err)
		}
	})
}

func TestCheckVersionNoTrustedKeys(t *testing.T) {
	d, srv := newDist(t)
	m := manifestBytes(t, "cli", "v1.2.0", srv.URL+"/x.tar.gz", goodSHA)
	d.put("/cli/manifest.json", m)

	t.Run("phase1 behaves as before and does not fetch the signature", func(t *testing.T) {
		warnings := withPolicy(t, false)
		if _, err := CheckVersion(srv.URL+"/cli/manifest.json", "linux", "amd64", "v1.1.0"); err != nil {
			t.Fatal(err)
		}
		if d.hits["/cli/manifest.json.sig"] != 0 || len(*warnings) != 0 {
			t.Fatalf("sig hits %d, warnings %v", d.hits["/cli/manifest.json.sig"], *warnings)
		}
	})
	t.Run("phase2 refuses", func(t *testing.T) {
		withPolicy(t, true)
		_, err := CheckVersion(srv.URL+"/cli/manifest.json", "linux", "amd64", "v1.1.0")
		if !errors.Is(err, ErrUnsigned) {
			t.Fatalf("err = %v, want ErrUnsigned", err)
		}
	})
}

// One key signs every product: a valid engine manifest served at the CLI's
// URL must not verify, or the CLI would install the engine over itself.
func TestCheckVersionWrongProduct(t *testing.T) {
	k := newKey(t)
	d, srv := newDist(t)
	m := manifestBytes(t, "engine", "v1.2.0", srv.URL+"/engine/v1.2.0/x.tar.gz", goodSHA)
	d.put("/cli/manifest.json", m)
	d.put("/cli/manifest.json.sig", []byte(SignManifest(k.priv, m)))
	withPolicy(t, false, k.pub)

	_, err := CheckVersion(srv.URL+"/cli/manifest.json", "linux", "amd64", "v1.1.0")
	if !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "product") {
		t.Fatalf("err = %v, want a product mismatch", err)
	}
}

func TestCheckVersionSignedWithoutSHA(t *testing.T) {
	k := newKey(t)
	d, srv := newDist(t)
	m := manifestBytes(t, "cli", "v1.2.0", srv.URL+"/x.tar.gz", "")
	d.put("/cli/manifest.json", m)
	d.put("/cli/manifest.json.sig", []byte(SignManifest(k.priv, m)))
	withPolicy(t, false, k.pub)

	if _, err := CheckVersion(srv.URL+"/cli/manifest.json", "linux", "amd64", "v1.1.0"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// Rotation: a .sig with a line per key verifies under either key.
func TestCheckVersionRotation(t *testing.T) {
	oldK, newK := newKey(t), newKey(t)
	d, srv := newDist(t)
	m := manifestBytes(t, "engine", "v1.2.0", srv.URL+"/x.tar.gz", goodSHA)
	d.put("/engine/channels/canary.json", m)
	d.put("/engine/channels/canary.json.sig", []byte("# rotating\n"+SignManifest(oldK.priv, m)+"\n"+SignManifest(newK.priv, m)))

	for name, key := range map[string]ed25519.PublicKey{"old binary": oldK.pub, "new binary": newK.pub} {
		t.Run(name, func(t *testing.T) {
			withPolicy(t, true, key)
			if _, err := CheckVersion(srv.URL+"/engine/channels/canary.json", "linux", "amd64", "v1.1.0"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCheckVersionMalformedSignature(t *testing.T) {
	k := newKey(t)
	d, srv := newDist(t)
	m := manifestBytes(t, "cli", "v1.2.0", srv.URL+"/x.tar.gz", goodSHA)
	d.put("/cli/manifest.json", m)
	withPolicy(t, false, k.pub)
	for _, sig := range []string{"", "not base64!", "AAAA"} {
		d.put("/cli/manifest.json.sig", []byte(sig))
		if _, err := CheckVersion(srv.URL+"/cli/manifest.json", "linux", "amd64", "v1.1.0"); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("sig %q: err = %v, want ErrBadSignature", sig, err)
		}
	}
}

func TestCheckVersionManifestNotFound(t *testing.T) {
	_, srv := newDist(t)
	withPolicy(t, false)
	if _, err := CheckVersion(srv.URL+"/cli/manifest.json", "linux", "amd64", "v1.1.0"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v, want a 404", err)
	}
}

func TestSignatureURL(t *testing.T) {
	cases := map[string]string{
		"https://dist.inference.sh/cli/manifest.json":       "https://dist.inference.sh/cli/manifest.json.sig",
		"https://dist.inference.sh/cli/manifest.json?t=123": "https://dist.inference.sh/cli/manifest.json.sig?t=123",
	}
	for in, want := range cases {
		got, err := SignatureURL(in)
		if err != nil || got != want {
			t.Errorf("SignatureURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestProductFromURL(t *testing.T) {
	cases := map[string]string{
		"https://dist.inference.sh/cli/manifest.json":           "cli",
		"https://dist.inference.sh/engine/channels/canary.json": "engine",
		"https://dist.inference.sh/engine/v1.2.3/manifest.json": "engine",
		"https://dist.inference.sh/manifest.json":               "",
		"http://127.0.0.1:8080/cli/manifest.json?x=/engine/a/b": "cli",
	}
	for in, want := range cases {
		if got := ProductFromURL(in); got != want {
			t.Errorf("ProductFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseKeys(t *testing.T) {
	k := newKey(t)
	if err := SetTrustedKeys("short"); err == nil {
		t.Fatal("SetTrustedKeys accepted a malformed key")
	}
	t.Cleanup(func() { _ = SetTrustedKeys() })
	pub, err := ParsePublicKey(EncodePublicKey(k.pub))
	if err != nil || !pub.Equal(k.pub) {
		t.Fatalf("public key round trip: %v", err)
	}
	for _, enc := range []string{
		"  " + b64(k.priv.Seed()) + "\n", // seed, as keygen prints it
		b64(k.priv),                      // expanded
	} {
		priv, err := ParsePrivateKey(enc)
		if err != nil || !priv.Equal(k.priv) {
			t.Fatalf("private key %q: %v", enc, err)
		}
	}
	bad := append([]byte{}, k.priv...)
	bad[40] ^= 1 // public half no longer matches the seed
	if _, err := ParsePrivateKey(b64(bad)); err == nil {
		t.Fatal("ParsePrivateKey accepted a mismatched expanded key")
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
