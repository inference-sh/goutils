// Package binresolve resolves and caches a platform-specific binary that is
// distributed via a manifest.json over HTTP. The typical use case is a CLI
// that wants to fetch a helper binary on demand and re-use it across runs
// — e.g. infsh downloading the engine binary to ~/.cache/inferencesh/bin/engine
// for local `infsh app test` commands.
//
// This is a generic sibling to the autoupdate package. Where autoupdate
// replaces the currently running binary, binresolve downloads a separate
// dependency into a cache directory.
package binresolve

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"inference.sh/goutils/binfetch"
	"inference.sh/goutils/updater"
)

// Config controls how the resolver downloads and caches a binary.
type Config struct {
	// ManifestURL points at the manifest.json for the binary, e.g.
	// https://dist.inference.sh/engine/manifest.json.
	ManifestURL string

	// BinaryName is the name of the binary within the extracted archive and
	// the final cached filename. `.exe` is appended automatically when
	// Platform is "windows".
	BinaryName string

	// CacheDir is the directory where the binary is cached. Required.
	// Convention: ~/.cache/<your-app>/ — the resolver creates a "bin/"
	// subdirectory inside it.
	CacheDir string

	// Platform and Arch default to runtime.GOOS / runtime.GOARCH.
	Platform string
	Arch     string

	// HTTPClient overrides the http.Client used for downloads.
	HTTPClient *http.Client

	// OnProgress is an optional download progress callback.
	OnProgress func(current, total int64)
}

// Resolver downloads and caches a binary on demand.
type Resolver struct {
	cfg        Config
	binDir     string // CacheDir/bin
	binaryPath string // CacheDir/bin/<name>[.exe]

	// versionCache memoises the result of asking the cached binary its
	// version (`<binary> version --short`) within a single Resolver lifetime
	// so we don't fork a subprocess on every Ensure call.
	versionCache string
}

// New returns a Resolver with sane defaults applied to cfg. ManifestURL,
// BinaryName, and CacheDir are required.
func New(cfg Config) (*Resolver, error) {
	if cfg.ManifestURL == "" {
		return nil, fmt.Errorf("binresolve: ManifestURL is required")
	}
	if cfg.BinaryName == "" {
		return nil, fmt.Errorf("binresolve: BinaryName is required")
	}
	if cfg.CacheDir == "" {
		return nil, fmt.Errorf("binresolve: CacheDir is required")
	}
	if cfg.Platform == "" {
		cfg.Platform = runtime.GOOS
	}
	if cfg.Arch == "" {
		cfg.Arch = runtime.GOARCH
	}

	binDir := filepath.Join(cfg.CacheDir, "bin")
	fileName := cfg.BinaryName
	if cfg.Platform == "windows" {
		fileName = fileName + ".exe"
	}

	return &Resolver{
		cfg:        cfg,
		binDir:     binDir,
		binaryPath: filepath.Join(binDir, fileName),
	}, nil
}

// Ensure returns a path to the cached binary, downloading it if missing or if
// the cached version is older than what the manifest advertises.
//
// If the manifest fetch fails but a cached copy exists, the cached path is
// returned so the caller can still make forward progress in offline scenarios.
func (r *Resolver) Ensure(ctx context.Context) (string, error) {
	info, err := updater.CheckVersion(r.cfg.ManifestURL, r.cfg.Platform, r.cfg.Arch, r.cachedVersion())
	if err != nil {
		if r.cacheExists() {
			return r.binaryPath, nil
		}
		return "", fmt.Errorf("check %s manifest: %w", r.cfg.BinaryName, err)
	}

	if !info.UpdateAvailable && r.cacheExists() {
		return r.binaryPath, nil
	}

	err = binfetch.DownloadAndInstallBinary(ctx, binfetch.BinFetchOptions{
		URL:            info.DownloadURL,
		ExpectedSHA256: info.SHA256,
		DestPath:       r.binaryPath,
		Windows:        r.cfg.Platform == "windows",
		HTTPClient:     r.cfg.HTTPClient,
		OnProgress:     r.cfg.OnProgress,
	})
	if err != nil {
		return "", fmt.Errorf("install %s: %w", r.cfg.BinaryName, err)
	}
	// Reset memoised version so the next call sees the freshly installed binary.
	r.versionCache = ""
	return r.binaryPath, nil
}

// Path returns the cached binary path without downloading. Returns empty
// string if nothing is cached yet.
func (r *Resolver) Path() string {
	if r.cacheExists() {
		return r.binaryPath
	}
	return ""
}

// BinaryPath returns the target path regardless of whether the file exists.
// Useful for logging and tests.
func (r *Resolver) BinaryPath() string {
	return r.binaryPath
}

func (r *Resolver) cacheExists() bool {
	info, err := os.Stat(r.binaryPath)
	return err == nil && !info.IsDir()
}

// cachedVersion asks the cached binary its own version by running
// `<binary> version --short`. This is the source of truth — if the binary on
// disk gets manually replaced, the version reported here matches reality
// instead of an out-of-band sidecar file. Returns "v0.0.0" if the binary is
// missing, errors out, or doesn't support the --short flag, which forces
// Ensure to download a fresh copy.
func (r *Resolver) cachedVersion() string {
	if r.versionCache != "" {
		return r.versionCache
	}
	if !r.cacheExists() {
		return "v0.0.0"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.binaryPath, "version", "--short")
	out, err := cmd.Output()
	if err != nil {
		return "v0.0.0"
	}
	v := strings.TrimSpace(string(out))
	// Sanity check: must look like a semver-ish token (starts with v or digit).
	if v == "" || (v[0] != 'v' && (v[0] < '0' || v[0] > '9')) {
		return "v0.0.0"
	}
	r.versionCache = v
	return v
}
