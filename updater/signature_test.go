package updater

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	cliMain    = "https://github.com/inference-sh/cli/.github/workflows/release.yml@refs/heads/main"
	cliDev     = "https://github.com/inference-sh/cli/.github/workflows/release.yml@refs/heads/dev"
	engineMain = "https://github.com/inference-sh/engine/.github/workflows/release.yml@refs/heads/main"
	engineDev  = "https://github.com/inference-sh/engine/.github/workflows/release.yml@refs/heads/dev"
)

// fakeSigstore stands in for Sigstore: a virtual CA and log as the trust
// root, and bundles served as tokens that parseBundle maps to the entities
// the virtual CA signed.
type fakeSigstore struct {
	t  *testing.T
	vs *ca.VirtualSigstore

	mu       sync.Mutex
	entities map[string]verify.SignedEntity
}

func newFakeSigstore(t *testing.T) *fakeSigstore {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSigstore{t: t, vs: vs, entities: map[string]verify.SignedEntity{}}

	prevTM, prevParse, prevOpts := trustedMaterial, parseBundle, verifierOptions
	trustedMaterial = func() (root.TrustedMaterial, error) { return vs, nil }
	parseBundle = func(b []byte) (verify.SignedEntity, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		e, ok := f.entities[string(b)]
		if !ok {
			return nil, errors.New("not a bundle")
		}
		return e, nil
	}
	// The virtual CA issues no SCTs; everything else is as in production.
	verifierOptions = []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}
	t.Cleanup(func() { trustedMaterial, parseBundle, verifierOptions = prevTM, prevParse, prevOpts })
	return f
}

// sign returns a bundle token for artifact signed as identity/issuer.
func (f *fakeSigstore) sign(identity, issuer string, artifact []byte) []byte {
	f.t.Helper()
	e, err := f.vs.Sign(identity, issuer, artifact)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	tok := fmt.Sprintf("bundle-%d", len(f.entities))
	f.entities[tok] = e
	return []byte(tok)
}

// manifestJSON is a stable v1.2.0 manifest for product ("" leaves the
// product and channel out, as in a manifest published before signing).
func manifestJSON(product, url, sha string) []byte {
	if product == "" {
		return manifestFor("", "", "v1.2.0", url, sha)
	}
	return manifestFor(product, "stable", "v1.2.0", url, sha)
}

func manifestFor(product, channel, version, url, sha string) []byte {
	m := map[string]any{
		"version": version,
		"builds":  map[string]any{"linux-amd64": map[string]string{"url": url, "sha256": sha}},
	}
	if product != "" {
		m["product"] = product
	}
	if channel != "" {
		m["channel"] = channel
	}
	b, _ := json.Marshal(m)
	return b
}

const goodSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// serve hosts manifest at /cli/manifest.json and, when bundle is non-nil,
// its bundle beside it.
func serve(t *testing.T, path string, manifest, bundle []byte) (url string, bundleHits *int) {
	t.Helper()
	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) { w.Write(manifest) })
	mux.HandleFunc(path+BundleSuffix, func(w http.ResponseWriter, _ *http.Request) {
		hits++
		if bundle == nil {
			http.NotFound(w, nil)
			return
		}
		w.Write(bundle)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL + path, &hits
}

func captureWarnings(t *testing.T) *[]string {
	var got []string
	prev := Warnf
	Warnf = func(format string, args ...any) { got = append(got, fmt.Sprintf(format, args...)) }
	t.Cleanup(func() { Warnf = prev })
	return &got
}

func setRequired(t *testing.T, product string, required bool) {
	prev := Products[product]
	p := prev
	p.Required = required
	Products[product] = p
	t.Cleanup(func() { Products[product] = prev })
}

func TestRolloutSwitchesStartOff(t *testing.T) {
	// Phase 1 ships with both off. Flipping one is a deliberate change to
	// this test as well.
	if CLISignatureRequired || EngineSignatureRequired {
		t.Fatal("a product requires signatures; update this test with the rollout")
	}
	for name, p := range Products {
		if p.Name != name || len(p.Channels) == 0 {
			t.Fatalf("product %q is incomplete: %+v", name, p)
		}
		for _, c := range p.Channels {
			if c.Signer.Repository == "" || len(c.Signer.Refs) == 0 || len(c.Paths) == 0 || c.Version == "" {
				t.Fatalf("product %q channel %q is incomplete: %+v", name, c.Name, c)
			}
		}
	}
}

func TestSignedManifestVerifies(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprint("required=", required), func(t *testing.T) {
			f := newFakeSigstore(t)
			setRequired(t, "cli", required)
			warns := captureWarnings(t)
			m := manifestJSON("cli", "https://dist.inference.sh/cli/v1.2.0/belt.tar.gz", goodSHA)
			url, _ := serve(t, "/cli/manifest.json", m, f.sign(cliMain, OIDCIssuer, m))

			info, err := CheckVersion(url, "linux", "amd64", "v1.0.0")
			if err != nil {
				t.Fatal(err)
			}
			if !info.Signed || !info.UpdateAvailable || info.SHA256 != goodSHA {
				t.Fatalf("info = %+v", info)
			}
			if len(*warns) != 0 {
				t.Fatalf("warnings: %v", *warns)
			}
		})
	}
}

func TestRefused(t *testing.T) {
	genuine := manifestJSON("cli", "https://dist.inference.sh/cli/v1.2.0/belt.tar.gz", goodSHA)
	cases := []struct {
		name     string
		served   []byte // manifest served
		signed   []byte // bytes the bundle covers
		identity string
		issuer   string
	}{
		{"tampered url", manifestJSON("cli", "https://evil.example/belt.tar.gz", goodSHA), genuine, cliMain, OIDCIssuer},
		{"tampered sha256", manifestJSON("cli", "https://dist.inference.sh/cli/v1.2.0/belt.tar.gz", strings.Repeat("b", 64)), genuine, cliMain, OIDCIssuer},
		{"other branch", genuine, genuine, "https://github.com/inference-sh/cli/.github/workflows/release.yml@refs/heads/attacker", OIDCIssuer},
		{"dev signs cli stable", genuine, genuine, cliDev, OIDCIssuer},
		{"no channel", manifestFor("cli", "", "v1.2.0", "u", goodSHA), manifestFor("cli", "", "v1.2.0", "u", goodSHA), cliMain, OIDCIssuer},
		{"canary channel on cli", manifestFor("cli", "canary", "v1.2.0-canary.0", "u", goodSHA), manifestFor("cli", "canary", "v1.2.0-canary.0", "u", goodSHA), cliMain, OIDCIssuer},
		{"prerelease version on stable", manifestFor("cli", "stable", "v1.2.0-canary.0", "u", goodSHA), manifestFor("cli", "stable", "v1.2.0-canary.0", "u", goodSHA), cliMain, OIDCIssuer},
		{"tag ref not allowed", genuine, genuine, "https://github.com/inference-sh/cli/.github/workflows/release.yml@refs/tags/v1.2.0", OIDCIssuer},
		{"other workflow", genuine, genuine, "https://github.com/inference-sh/cli/.github/workflows/ci.yml@refs/heads/dev", OIDCIssuer},
		{"other repo", genuine, genuine, "https://github.com/inference-sh/engine/.github/workflows/release.yml@refs/heads/dev", OIDCIssuer},
		{"identity prefix", genuine, genuine, cliMain + "x", OIDCIssuer},
		{"other issuer", genuine, genuine, cliMain, "https://accounts.google.com"},
		{"wrong product", manifestJSON("engine", "u", goodSHA), manifestJSON("engine", "u", goodSHA), cliMain, OIDCIssuer},
		{"no product", manifestJSON("", "u", goodSHA), manifestJSON("", "u", goodSHA), cliMain, OIDCIssuer},
		{"signed but no sha256", manifestJSON("cli", "u", ""), manifestJSON("cli", "u", ""), cliMain, OIDCIssuer},
	}
	for _, tc := range cases {
		for _, required := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/required=%v", tc.name, required), func(t *testing.T) {
				f := newFakeSigstore(t)
				setRequired(t, "cli", required)
				url, _ := serve(t, "/cli/manifest.json", tc.served, f.sign(tc.identity, tc.issuer, tc.signed))
				_, err := CheckVersion(url, "linux", "amd64", "v1.0.0")
				if !errors.Is(err, ErrBadSignature) {
					t.Fatalf("err = %v, want ErrBadSignature", err)
				}
			})
		}
	}
}

func TestEngineIdentityCannotSignCLI(t *testing.T) {
	// An engine release run can't make a manifest the CLI installs, even
	// one that says "cli".
	f := newFakeSigstore(t)
	m := manifestJSON("cli", "u", goodSHA)
	url, _ := serve(t, "/cli/manifest.json", m, f.sign(engineMain, OIDCIssuer, m))
	if _, err := CheckVersion(url, "linux", "amd64", "v1.0.0"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestUnsignedPhase1WarnsPhase2Refuses(t *testing.T) {
	newFakeSigstore(t)
	m := manifestJSON("", "u", goodSHA)

	t.Run("phase 1", func(t *testing.T) {
		warns := captureWarnings(t)
		url, hits := serve(t, "/cli/manifest.json", m, nil)
		info, err := CheckVersion(url, "linux", "amd64", "v1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		if info.Signed || *hits != 1 || len(*warns) != 1 || !strings.Contains((*warns)[0], "not signed") {
			t.Fatalf("signed=%v bundle fetches=%d warnings=%v", info.Signed, *hits, *warns)
		}
	})
	t.Run("phase 2", func(t *testing.T) {
		setRequired(t, "cli", true)
		url, _ := serve(t, "/cli/manifest.json", m, nil)
		if _, err := CheckVersion(url, "linux", "amd64", "v1.0.0"); !errors.Is(err, ErrUnsigned) {
			t.Fatalf("err = %v, want ErrUnsigned", err)
		}
	})
	t.Run("required is per product", func(t *testing.T) {
		setRequired(t, "engine", true)
		captureWarnings(t)
		url, _ := serve(t, "/cli/manifest.json", m, nil)
		if _, err := CheckVersion(url, "linux", "amd64", "v1.0.0"); err != nil {
			t.Fatalf("cli refused because engine requires signatures: %v", err)
		}
	})
}

func TestUnknownProductIsNotChecked(t *testing.T) {
	newFakeSigstore(t)
	warns := captureWarnings(t)
	url, hits := serve(t, "/manifest.json", manifestJSON("", "u", goodSHA), nil)
	if _, err := CheckVersion(url, "linux", "amd64", "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	if *hits != 0 || len(*warns) != 0 {
		t.Fatalf("bundle fetches=%d warnings=%v", *hits, *warns)
	}
}

func TestBundleFetchErrorFails(t *testing.T) {
	newFakeSigstore(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/cli/manifest.json", func(w http.ResponseWriter, _ *http.Request) { w.Write(manifestJSON("cli", "u", goodSHA)) })
	mux.HandleFunc("/cli/manifest.json"+BundleSuffix, func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	// Only a 404 means unsigned; anything else must not fall back to it.
	if _, err := CheckVersion(srv.URL+"/cli/manifest.json", "linux", "amd64", "v1.0.0"); err == nil || errors.Is(err, ErrUnsigned) {
		t.Fatalf("err = %v, want a fetch error", err)
	}
}

func TestGarbageBundleFails(t *testing.T) {
	newFakeSigstore(t)
	url, _ := serve(t, "/cli/manifest.json", manifestJSON("cli", "u", goodSHA), []byte("{}"))
	if _, err := CheckVersion(url, "linux", "amd64", "v1.0.0"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestManifest404(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := CheckVersion(srv.URL+"/cli/manifest.json", "linux", "amd64", "v1.0.0"); err == nil {
		t.Fatal("want an error")
	}
}

func TestVerifyManifestFiles(t *testing.T) {
	f := newFakeSigstore(t)
	dir := t.TempDir()
	m := manifestJSON("cli", "u", goodSHA)
	write := func(name string, b []byte) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mp := write("manifest.json", m)
	bp := write("manifest.json.sigstore.json", f.sign(cliMain, OIDCIssuer, m))
	san, err := VerifyManifestFiles(mp, bp, "cli", "v1.2.0/manifest.json", "manifest.json")
	if err != nil || san != cliMain {
		t.Fatalf("san=%q err=%v", san, err)
	}
	if _, err := VerifyManifestFiles(mp, bp, "cli", "manifest.json", "v1.2.1/manifest.json"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("another version's path: err = %v, want ErrBadSignature", err)
	}
	if _, err := VerifyManifestFiles(mp, bp, "cli"); err == nil {
		t.Fatal("no dist path: want an error")
	}
	if _, err := VerifyManifestFiles(mp, bp, "engine", "manifest.json"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("engine: err = %v, want ErrBadSignature", err)
	}
	empty := manifestJSON("cli", "u", "")
	mp2 := write("m2.json", empty)
	bp2 := write("m2.json.sigstore.json", f.sign(cliMain, OIDCIssuer, empty))
	if _, err := VerifyManifestFiles(mp2, bp2, "cli", "manifest.json"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("no sha256: err = %v, want ErrBadSignature", err)
	}
}

// A real public-good bundle (goreleaser v2.20.2's checksums.txt, signed
// keyless by its GitHub release workflow) against the production verifier
// options and the trust root compiled into this package, offline.
func TestRealPublicGoodBundle(t *testing.T) {
	prev := trustedMaterial
	trustedMaterial = func() (root.TrustedMaterial, error) { return root.NewTrustedRootFromJSON(embeddedTrustedRoot) }
	t.Cleanup(func() { trustedMaterial = prev })

	artifact, err := os.ReadFile("testdata/goreleaser-v2.20.2-checksums.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("testdata/goreleaser-v2.20.2-checksums.txt.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	signedBy := func(ref string) Product {
		return Product{Name: "goreleaser", Channels: []Channel{{
			Name:    "stable",
			Signer:  Signer{Repository: "goreleaser/goreleaser", Workflow: ".github/workflows/release.yml", Refs: []string{ref}},
			Paths:   []string{"checksums.txt"},
			Version: ".*",
		}}}
	}
	goreleaser := signedBy("refs/tags/v2.20.2")

	// The signature, certificate chain, SCT, Rekor entry and identity all
	// verify; what fails is the product check, since checksums.txt is not a
	// manifest.
	_, err = VerifyManifest(artifact, b, goreleaser, "checksums.txt")
	if err == nil || !strings.Contains(err.Error(), "parse signed manifest") {
		t.Fatalf("err = %v, want it to get as far as the product check", err)
	}

	for name, p := range map[string]Product{
		"another signer": Products["cli"],
		"another ref":    signedBy("refs/heads/main"),
	} {
		if _, err := VerifyManifest(artifact, b, p, "checksums.txt"); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("%s: err = %v, want ErrBadSignature", name, err)
		}
	}
	tampered := append([]byte("x"), artifact...)
	if _, err := VerifyManifest(tampered, b, goreleaser, "checksums.txt"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered: err = %v, want ErrBadSignature", err)
	}
}

func TestBundleURL(t *testing.T) {
	got, err := BundleURL("https://dist.inference.sh/engine/channels/canary.json?x=1")
	if err != nil || got != "https://dist.inference.sh/engine/channels/canary.json.sigstore.json?x=1" {
		t.Fatalf("got %q, %v", got, err)
	}
	for in, want := range map[string]string{
		"https://dist.inference.sh/cli/manifest.json":           "cli",
		"https://dist.inference.sh/engine/v1.2.3/manifest.json": "engine",
		"https://dist.inference.sh/engine/channels/canary.json": "engine",
		"https://dist.inference.sh/manifest.json":               "",
	} {
		if got := ProductFromURL(in); got != want {
			t.Errorf("ProductFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEmbeddedTrustedRootParses(t *testing.T) {
	tr, err := root.NewTrustedRootFromJSON(embeddedTrustedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.FulcioCertificateAuthorities()) == 0 || len(tr.RekorLogs()) == 0 || len(tr.CTLogs()) == 0 {
		t.Fatal("embedded trusted root is missing Fulcio, Rekor or CT material")
	}
}

func TestSelfCheck(t *testing.T) {
	f := newFakeSigstore(t)
	dir := t.TempDir()
	m := manifestJSON("cli", "u", goodSHA) // version v1.2.0
	mp, bp := dir+"/manifest.json", dir+"/manifest.json.sigstore.json"
	if err := os.WriteFile(mp, m, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bp, f.sign(cliMain, OIDCIssuer, m), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, ok := RunSelfCheck([]string{"belt", SelfCheckCommand, "cli", mp, bp, "manifest.json"}, "v1.2.0"); !ok || code != 0 {
		t.Fatalf("code=%d ok=%v", code, ok)
	}
	if code, _ := RunSelfCheck([]string{"belt", SelfCheckCommand, "cli", mp, bp, "manifest.json"}, "v1.1.0"); code != 1 {
		t.Fatalf("version mismatch: code=%d, want 1", code)
	}
	if code, _ := RunSelfCheck([]string{"belt", SelfCheckCommand, "engine", mp, bp, "manifest.json"}, "v1.2.0"); code != 1 {
		t.Fatalf("wrong product: code=%d, want 1", code)
	}
	if code, _ := RunSelfCheck([]string{"belt", SelfCheckCommand, "cli", mp, bp}, "v1.2.0"); code != 2 {
		t.Fatalf("usage: code=%d, want 2", code)
	}
	if _, ok := RunSelfCheck([]string{"belt", "version"}, "v1.2.0"); ok {
		t.Fatal("handled an ordinary command")
	}
}

// The channel table: each engine channel is accepted only at its own paths,
// signed from its own branch, with its own kind of version. A dev-signed
// manifest is never accepted as stable.
func TestEngineChannels(t *testing.T) {
	stable := manifestFor("engine", "stable", "v1.2.0", "u", goodSHA)
	canary := manifestFor("engine", "canary", "v1.2.0-canary.3", "u", goodSHA)
	devStable := manifestFor("engine", "stable", "v1.2.0", "u", goodSHA)
	devCanaryStableVersion := manifestFor("engine", "canary", "v1.2.0", "u", goodSHA)
	cases := []struct {
		name     string
		path     string
		manifest []byte
		identity string
		ok       bool
	}{
		{"stable head, main", "/engine/manifest.json", stable, engineMain, true},
		{"stable version, main", "/engine/v1.2.0/manifest.json", stable, engineMain, true},
		{"canary head, dev", "/engine/channels/canary.json", canary, engineDev, true},
		{"canary version, dev", "/engine/v1.2.0-canary.3/manifest.json", canary, engineDev, true},

		{"canary served as stable head", "/engine/manifest.json", canary, engineDev, false},
		{"dev signs a stable manifest", "/engine/manifest.json", devStable, engineDev, false},
		{"dev signs stable at a version path", "/engine/v1.2.0/manifest.json", devStable, engineDev, false},
		{"dev canary with a stable version", "/engine/v1.2.0/manifest.json", devCanaryStableVersion, engineDev, false},
		{"stable served as canary head", "/engine/channels/canary.json", stable, engineMain, false},
		{"main signs a canary", "/engine/channels/canary.json", canary, engineMain, false},
		{"another version's path", "/engine/v1.2.1/manifest.json", stable, engineMain, false},
		{"another canary's path", "/engine/v1.2.0-canary.4/manifest.json", canary, engineDev, false},
		{"unknown path", "/engine/channels/beta.json", canary, engineDev, false},
		{"cli workflow signs engine", "/engine/manifest.json", stable, cliMain, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSigstore(t)
			url, _ := serve(t, tc.path, tc.manifest, f.sign(tc.identity, OIDCIssuer, tc.manifest))
			info, err := CheckVersion(url, "linux", "amd64", "v1.0.0")
			if tc.ok {
				if err != nil || !info.Signed {
					t.Fatalf("info=%+v err=%v, want a verified manifest", info, err)
				}
				return
			}
			if !errors.Is(err, ErrBadSignature) {
				t.Fatalf("err = %v, want ErrBadSignature", err)
			}
		})
	}
}

func TestDistPathFromURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://dist.inference.sh/engine/channels/canary.json?x=1": "channels/canary.json",
		"https://dist.inference.sh/engine/v1.2.3/manifest.json":     "v1.2.3/manifest.json",
		"https://dist.inference.sh/cli/manifest.json":               "manifest.json",
		"https://dist.inference.sh/manifest.json":                   "",
	} {
		if got := DistPathFromURL(in); got != want {
			t.Errorf("DistPathFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}
