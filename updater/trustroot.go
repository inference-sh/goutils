package updater

import (
	_ "embed"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// The trust root (Fulcio CAs, Rekor and CT log keys) comes from Sigstore's
// public-good TUF repository. The TUF root of trust, root.json, is compiled
// in (sigstore-go embeds it), and the client walks it forward to the
// current trusted_root.json, so Sigstore can rotate its keys without a new
// binary. The metadata is cached on disk and refreshed at most once a day.
//
// When TUF can't be reached and nothing is cached, the snapshot of
// trusted_root.json compiled in here is used (go generate refreshes it). An
// update check that reaches dist but not the TUF CDN still verifies; what
// it can't do is learn of a Sigstore key revoked after the snapshot.

//go:generate go run ./internal/gentrustedroot trusted_root.json

//go:embed trusted_root.json
var embeddedTrustedRoot []byte

var (
	tufCacheMu  sync.Mutex
	tufCacheDir string

	trustMu     sync.Mutex
	trustCached root.TrustedMaterial
	trustAt     time.Time
)

// SetSigstoreCacheDir sets where the TUF metadata is cached. The default is
// <user cache dir>/inference.sh/sigstore-tuf.
func SetSigstoreCacheDir(dir string) {
	tufCacheMu.Lock()
	tufCacheDir = dir
	tufCacheMu.Unlock()
}

func sigstoreCacheDir() string {
	tufCacheMu.Lock()
	defer tufCacheMu.Unlock()
	if tufCacheDir != "" {
		return tufCacheDir
	}
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "inference.sh", "sigstore-tuf")
	}
	return ""
}

// trustedMaterial is the trust root bundles are verified against. Tests
// replace it with a virtual Sigstore.
var trustedMaterial = func() (root.TrustedMaterial, error) {
	trustMu.Lock()
	defer trustMu.Unlock()
	// A long-running engine checks for updates for days; reread the cache
	// (and so refresh it when it is a day old) at most hourly.
	if trustCached != nil && time.Since(trustAt) < time.Hour {
		return trustCached, nil
	}
	tr, err := tufTrustedRoot()
	if err != nil {
		tr, err = root.NewTrustedRootFromJSON(embeddedTrustedRoot)
		if err != nil {
			return nil, err
		}
	}
	trustCached, trustAt = tr, time.Now()
	return tr, nil
}

func tufTrustedRoot() (*root.TrustedRoot, error) {
	opts := tuf.DefaultOptions().WithCacheValidity(1)
	if dir := sigstoreCacheDir(); dir != "" {
		opts = opts.WithCachePath(dir)
	} else {
		opts = opts.WithDisableLocalCache()
	}
	// Bounded, like the manifest fetch: this runs before a command.
	f := fetcher.NewDefaultFetcher()
	f.SetHTTPClient(&http.Client{Timeout: 10 * time.Second})
	opts = opts.WithFetcher(f)
	c, err := tuf.New(opts)
	if err != nil {
		return nil, err
	}
	return root.GetTrustedRoot(c)
}
