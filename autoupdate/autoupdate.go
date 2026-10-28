// Package autoupdate implements transparent self-update for CLI binaries.
//
// Typical usage from a binary's main() entrypoint, before any other work:
//
//	_ = autoupdate.CheckAndReexec(ctx, autoupdate.Config{
//	    ManifestURL:    constants.CLIManifestURL,
//	    CurrentVersion: version.Version,
//	    CheckInterval:  6 * time.Hour,
//	    DisabledEnv:    "INFSH_NO_AUTOUPDATE",
//	    Logf:           ui.Infof,
//	})
//
// When an update is found, CheckAndReexec downloads it via
// common-go/pkg/binfetch.DownloadAndInstallBinary, atomically swaps the running
// binary, and re-executes the current process with the same argv so the
// caller continues as if nothing happened.
//
// Auto-update is best-effort. All failures (network, permission, corrupt
// archive) are returned to the caller but most callers should ignore them —
// the goal is transparent updates, not enforced updates.
package autoupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/inference-sh/goutils/binfetch"
	"github.com/inference-sh/goutils/dirs"
	"github.com/inference-sh/goutils/fileutil"
	"github.com/inference-sh/goutils/reexec"
	"github.com/inference-sh/goutils/updater"
)

// Config declares how a binary should auto-update itself.
type Config struct {
	// ManifestURL points at the manifest.json for this binary, e.g.
	// https://dist.inference.sh/cli/manifest.json
	ManifestURL string

	// CurrentVersion is this binary's version, typically injected via
	// -ldflags at build time. If empty or equal to "dev", auto-update is
	// skipped entirely so local dev builds aren't clobbered.
	CurrentVersion string

	// CheckInterval is the minimum time between checks. If a previous check
	// happened within this window the function returns immediately without
	// touching the network. Zero disables rate limiting (always check).
	CheckInterval time.Duration

	// Force overrides the dev-build and rate-limit guards so the update
	// check always hits the network. Useful for escaping a dev build.
	Force bool

	// DisabledEnv is the name of an environment variable that, when set to
	// any non-empty value, disables auto-update. Typical: "INFSH_NO_AUTOUPDATE".
	DisabledEnv string

	// StateDir is where the last-check timestamp is persisted. Defaults to
	// ~/.cache/inferencesh/autoupdate.
	StateDir string

	// OnProgress is an optional download progress callback.
	OnProgress func(current, total int64)

	// Logf is an optional logger for user-facing status messages.
	// Defaults to a no-op.
	Logf func(format string, args ...any)

	// Platform / Arch default to runtime.GOOS / runtime.GOARCH.
	Platform string
	Arch     string

	// SelfPath is the binary an update replaces. Empty is the running
	// binary. Symlinks are resolved either way, so the update replaces the
	// file a link points at and the link keeps working.
	SelfPath string

	// Package is this binary's name in a package manager, for the command
	// that updates it there, e.g. "belt" for "brew upgrade belt". Empty is
	// the binary's file name without its extension.
	Package string

	// Exact makes Prepare plan the manifest's version whenever it differs
	// from CurrentVersion, older included: for a manifest that names the
	// build to run, such as a pinned version or a channel being left.
	// CheckAndReexec ignores it and only ever moves forward.
	Exact bool

	// Testing hooks — unexported, set via helpers in tests.
	nowFn  func() time.Time
	execFn func(path string, args []string) error
}

// Result reports the outcome of a CheckAndReexec call.
type Result struct {
	Skipped         bool   // true if we bailed out early (disabled, dev, recent check)
	SkipReason      string // human-readable reason when Skipped is true
	UpdateAvailable bool   // whether the manifest advertised a newer version
	FromVersion     string
	ToVersion       string
	// PackageManager is set when the binary was installed via a package manager
	// (e.g. "brew upgrade belt"). Self-update is skipped; the caller should
	// surface this command to the user instead.
	PackageManager string
	// ReexecAttempted is true if we reached the re-exec step. On Unix this
	// never actually returns on success (the syscall replaces the process),
	// so seeing ReexecAttempted=true in the returned Result implies the exec
	// failed.
	ReexecAttempted bool
}

// state is the on-disk cache of the last check result.
type state struct {
	LastCheck   time.Time `json:"lastCheck"`
	LastVersion string    `json:"lastVersion,omitempty"`
	DownloadURL string    `json:"downloadURL,omitempty"`
	SHA256      string    `json:"sha256,omitempty"`
	Aliases     []string  `json:"aliases,omitempty"`
	// FailedVersion / FailedAt record the last install attempt that failed,
	// so a broken update (locked exe, full disk) is retried on a backoff
	// instead of re-downloading on every command.
	FailedVersion string    `json:"failedVersion,omitempty"`
	FailedAt      time.Time `json:"failedAt,omitempty"`
}

// installRetryBackoff is how long a failed install of a given version is left
// alone before it is attempted again.
const installRetryBackoff = time.Hour

// CheckAndReexec implements the full self-update flow. See package doc.
func CheckAndReexec(ctx context.Context, cfg Config) (*Result, error) {
	applyDefaults(&cfg)

	if cfg.DisabledEnv != "" {
		if v := os.Getenv(cfg.DisabledEnv); v != "" {
			return &Result{Skipped: true, SkipReason: "disabled via " + cfg.DisabledEnv}, nil
		}
	}

	if !cfg.Force && isDevVersion(cfg.CurrentVersion) {
		return &Result{Skipped: true, SkipReason: "dev build"}, nil
	}

	// Rate-limit network checks, but if the cache has a newer version with
	// download info, use it directly without hitting the network.
	var info *updater.UpdateInfo
	if cfg.CheckInterval > 0 {
		st, _ := readState(stateFile(cfg))
		if st != nil && cfg.nowFn().Sub(st.LastCheck) < cfg.CheckInterval {
			if st.LastVersion != "" && st.DownloadURL != "" && updater.IsNewerVersion(st.LastVersion, cfg.CurrentVersion) {
				info = &updater.UpdateInfo{
					UpdateAvailable:  true,
					AvailableVersion: st.LastVersion,
					DownloadURL:      st.DownloadURL,
					SHA256:           st.SHA256,
					Aliases:          st.Aliases,
				}
			} else {
				return &Result{Skipped: true, SkipReason: "within check interval"}, nil
			}
		}
	}

	if info == nil {
		var err error
		info, err = updater.CheckVersion(cfg.ManifestURL, cfg.Platform, cfg.Arch, cfg.CurrentVersion)
		if err != nil {
			return nil, fmt.Errorf("check manifest: %w", err)
		}

		next := &state{
			LastCheck:   cfg.nowFn(),
			LastVersion: info.AvailableVersion,
			DownloadURL: info.DownloadURL,
			SHA256:      info.SHA256,
			Aliases:     info.Aliases,
		}
		if prev, _ := readState(stateFile(cfg)); prev != nil {
			next.FailedVersion, next.FailedAt = prev.FailedVersion, prev.FailedAt
		}
		_ = writeState(stateFile(cfg), next)

		if !info.UpdateAvailable {
			return &Result{
				FromVersion:     cfg.CurrentVersion,
				ToVersion:       info.AvailableVersion,
				UpdateAvailable: false,
			}, nil
		}
	}

	selfPath, err := cfg.binary()
	if err != nil {
		return nil, fmt.Errorf("locate current binary: %w", err)
	}

	// If installed via a package manager, don't attempt self-update —
	// overwriting a managed binary confuses the package manager's version
	// tracking. Return the update info so callers can surface it.
	if cmd := packageManagerUpdateCmd(selfPath, cfg.Package); cmd != "" {
		return &Result{
			UpdateAvailable: true,
			FromVersion:     cfg.CurrentVersion,
			ToVersion:       info.AvailableVersion,
			PackageManager:  cmd,
		}, nil
	}

	if st, _ := readState(stateFile(cfg)); st != nil && !cfg.Force &&
		st.FailedVersion == info.AvailableVersion && cfg.nowFn().Sub(st.FailedAt) < installRetryBackoff {
		return &Result{
			Skipped:         true,
			SkipReason:      "previous install attempt failed recently",
			UpdateAvailable: true,
			FromVersion:     cfg.CurrentVersion,
			ToVersion:       info.AvailableVersion,
		}, nil
	}

	cfg.Logf("updating %s -> %s...", cfg.CurrentVersion, info.AvailableVersion)

	// Check the destination directory is writable.
	if err := checkWritable(selfPath); err != nil {
		recordInstallFailure(cfg, info.AvailableVersion)
		return nil, err
	}

	if err := installOverSelf(ctx, selfPath, info, cfg); err != nil {
		recordInstallFailure(cfg, info.AvailableVersion)
		cfg.Logf("update to %s failed, continuing with %s: %v", info.AvailableVersion, cfg.CurrentVersion, err)
		return nil, fmt.Errorf("install update: %w", err)
	}

	res := &Result{
		FromVersion:     cfg.CurrentVersion,
		ToVersion:       info.AvailableVersion,
		UpdateAvailable: true,
		ReexecAttempted: true,
	}

	// Re-exec the current process with the same argv. On Unix this does not
	// return on success.
	if err := cfg.execFn(selfPath, os.Args); err != nil {
		return res, fmt.Errorf("re-exec: %w", err)
	}
	return res, nil
}

// recordInstallFailure stamps the state file so the next commands skip this
// version until installRetryBackoff has passed.
func recordInstallFailure(cfg Config, version string) {
	st, _ := readState(stateFile(cfg))
	if st == nil {
		st = &state{}
	}
	st.FailedVersion = version
	st.FailedAt = cfg.nowFn()
	_ = writeState(stateFile(cfg), st)
}

// installOverSelf downloads the new archive and replaces the running binary.
// The Unix case relies on the kernel's inode semantics: os.Rename over a
// running binary succeeds because the currently-executing file is held by
// the kernel until the process exits.
//
// Aliases declared in the manifest (e.g. "infsh" alongside "inferencesh") are
// recreated as symlinks in the same directory after install, so freshly
// updated binaries pick up new aliases automatically without re-running
// install.sh.
func installOverSelf(ctx context.Context, selfPath string, info *updater.UpdateInfo, cfg Config) error {
	return binfetch.DownloadAndInstallBinary(ctx, binfetch.BinFetchOptions{
		URL:            info.DownloadURL,
		ExpectedSHA256: info.SHA256,
		DestPath:       selfPath,
		Windows:        cfg.Platform == "windows",
		OnProgress:     cfg.OnProgress,
		Aliases:        info.Aliases,
	})
}

// checkWritable verifies the directory containing path is writable by the
// current user. Returns a typed error on failure so callers can detect
// "install via package manager" situations.
func checkWritable(path string) error {
	dir := filepath.Dir(path)
	// Probe with a dot-prefixed temp file so it is hidden from tab-completion
	// if it somehow gets left behind.
	probe, err := os.CreateTemp(dir, ".autoupdate-probe-*")
	if err != nil {
		return &ErrNotWritable{Path: path, Err: err}
	}
	probe.Close()
	_ = os.Remove(probe.Name())
	return nil
}

// ErrNotWritable is returned when the directory containing the binary is not
// writable by the current user (e.g. Homebrew installs into /usr/local/bin).
type ErrNotWritable struct {
	Path string
	Err  error
}

func (e *ErrNotWritable) Error() string {
	return fmt.Sprintf("cannot self-update: %s is not writable (%v)", filepath.Dir(e.Path), e.Err)
}

// PackageManagerUpdateCmd detects whether the binary at binPath was installed
// by a package manager and returns the command that updates it there, e.g.
// "brew upgrade belt" for pkg "belt" (empty pkg is the binary's file name).
// Returns "" if no package manager owns the binary. binPath may be a symlink:
// Homebrew links /usr/local/bin/belt to its Cellar, and the link's own path
// says nothing about who installed it.
func PackageManagerUpdateCmd(binPath, pkg string) string {
	if resolved, err := filepath.EvalSymlinks(binPath); err == nil {
		binPath = resolved
	}
	return packageManagerUpdateCmd(binPath, pkg)
}

func packageManagerUpdateCmd(binPath, pkg string) string {
	p := filepath.ToSlash(binPath)
	if pkg == "" {
		pkg = strings.TrimSuffix(filepath.Base(binPath), ".exe")
	}

	// The resolved binary path is the ground truth. Package managers install
	// into well-known directory structures — if the path doesn't match, this
	// is a direct install and we should self-update regardless of what package
	// managers happen to be installed on the system.

	if strings.Contains(p, "/Cellar/") || strings.Contains(p, "/homebrew/") {
		return "brew upgrade " + pkg
	}

	if strings.Contains(p, "/scoop/apps/") {
		return "scoop update " + pkg
	}

	return ""
}

func (e *ErrNotWritable) Unwrap() error { return e.Err }

// applyDefaults fills in zero-valued fields with sensible defaults.
func applyDefaults(cfg *Config) {
	if cfg.Platform == "" {
		cfg.Platform = runtime.GOOS
	}
	if cfg.Arch == "" {
		cfg.Arch = runtime.GOARCH
	}
	if cfg.Logf == nil {
		cfg.Logf = func(format string, args ...any) {}
	}
	if cfg.nowFn == nil {
		cfg.nowFn = time.Now
	}
	if cfg.execFn == nil {
		cfg.execFn = reexec.Exec
	}
	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Join(dirs.GetCacheDirectory(), "autoupdate")
	}
}

// CachedUpdateAvailable checks the on-disk cache (no network call) and
// returns the available version if it's newer than currentVersion and the
// cache is fresher than maxAge. Returns "" if no update is pending.
func CachedUpdateAvailable(manifestURL, currentVersion string, maxAge time.Duration) string {
	cfg := Config{ManifestURL: manifestURL}
	applyDefaults(&cfg)
	st, _ := readState(stateFile(cfg))
	if st == nil || st.LastVersion == "" {
		return ""
	}
	if maxAge > 0 && time.Since(st.LastCheck) > maxAge {
		return ""
	}
	if !updater.IsNewerVersion(st.LastVersion, currentVersion) {
		return ""
	}
	return st.LastVersion
}

// ClearCache removes the on-disk state file for a given manifest URL,
// so subsequent CachedLatestVersion calls return "" until the next check.
func ClearCache(manifestURL string) {
	cfg := Config{ManifestURL: manifestURL}
	applyDefaults(&cfg)
	_ = os.Remove(stateFile(cfg))
}

// stateFile returns the path to the last-check timestamp file for a given
// manifest URL. We key by URL so a single cache dir can track multiple
// binaries (CLI and engine) without collision.
func stateFile(cfg Config) string {
	// Sanitise manifest URL into a filename-safe key.
	key := strings.NewReplacer(
		"https://", "",
		"http://", "",
		"/", "_",
		":", "_",
	).Replace(cfg.ManifestURL)
	return filepath.Join(cfg.StateDir, key+".json")
}

// readState loads the state file. Missing or corrupt state returns nil, nil
// so callers treat it as "no prior check". So does a state file another
// user could have written (not owned by this process's user, or writable
// by its group or by everyone): a cached state names the download and
// its checksum, and is installed without a manifest read, so whoever can
// write it picks the binary this process, perhaps root, runs next.
func readState(path string) (*state, error) {
	data, err := fileutil.ReadOwnFile(path)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, fileutil.ErrNotOwn) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, nil // treat corrupt state as "no prior check"
	}
	return &s, nil
}

// writeState persists the timestamp file. Best-effort — errors are ignored by
// the caller since missing state just means "check again next time". A new
// file is renamed over the old, so a link planted at path is replaced, not
// followed, and the file is this process's user's.
func writeState(path string, s *state) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WriteFileAtomic(path, bytes.NewReader(data), 0o644)
}

// binary returns the canonical path of the binary an update replaces,
// SelfPath or the running one, following symlinks so an update replaces the
// real file, not a link to it.
func (cfg Config) binary() (string, error) {
	exe := cfg.SelfPath
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return "", err
		}
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return exe, nil
	}
	return resolved, nil
}

// isDevVersion returns true for version strings we treat as "not a release"
// so auto-update can skip them.
func isDevVersion(v string) bool {
	if v == "" || v == "dev" {
		return true
	}
	// Typical go-build ldflags fallback: "v0.0.0-20250410123456-abcdef".
	// These are allowed — they still sort below any real tag. We only want to
	// bail out for the literal strings above.
	return false
}
