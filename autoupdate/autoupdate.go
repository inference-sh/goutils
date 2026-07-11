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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/inference-sh/goutils/binfetch"
	"github.com/inference-sh/goutils/dirs"
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

	// Testing hooks — unexported, set via helpers in tests.
	nowFn    func() time.Time
	execFn   func(path string, args []string) error
	selfPath func() (string, error)
}

// Result reports the outcome of a CheckAndReexec call.
type Result struct {
	Skipped         bool   // true if we bailed out early (disabled, dev, recent check)
	SkipReason      string // human-readable reason when Skipped is true
	UpdateAvailable bool   // whether the manifest advertised a newer version
	FromVersion     string
	ToVersion       string
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
}

// CheckAndReexec implements the full self-update flow. See package doc.
func CheckAndReexec(ctx context.Context, cfg Config) (*Result, error) {
	applyDefaults(&cfg)

	if cfg.DisabledEnv != "" {
		if v := os.Getenv(cfg.DisabledEnv); v != "" {
			return &Result{Skipped: true, SkipReason: "disabled via " + cfg.DisabledEnv}, nil
		}
	}

	if isDevVersion(cfg.CurrentVersion) {
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

		_ = writeState(stateFile(cfg), &state{
			LastCheck:   cfg.nowFn(),
			LastVersion: info.AvailableVersion,
			DownloadURL: info.DownloadURL,
			SHA256:      info.SHA256,
			Aliases:     info.Aliases,
		})

		if !info.UpdateAvailable {
			return &Result{
				FromVersion:     cfg.CurrentVersion,
				ToVersion:       info.AvailableVersion,
				UpdateAvailable: false,
			}, nil
		}
	}

	selfPath, err := cfg.selfPath()
	if err != nil {
		return nil, fmt.Errorf("locate current binary: %w", err)
	}

	cfg.Logf("updating %s -> %s...", cfg.CurrentVersion, info.AvailableVersion)

	// If installed via a package manager, redirect to the right update command
	// regardless of write permissions — overwriting a managed binary confuses
	// the package manager's version tracking.
	if cmd := packageManagerUpdateCmd(selfPath); cmd != "" {
		return nil, fmt.Errorf("installed via a package manager — run `%s` instead", cmd)
	}

	// Check the destination directory is writable.
	if err := checkWritable(selfPath); err != nil {
		return nil, err
	}

	if err := installOverSelf(ctx, selfPath, info, cfg); err != nil {
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

// packageManagerUpdateCmd detects whether belt was installed by a package
// manager and returns the appropriate update command. It checks the resolved
// binary path first (fast, no exec), then falls back to asking the package
// manager directly if the path is ambiguous.
func packageManagerUpdateCmd(binPath string) string {
	p := filepath.ToSlash(binPath)

	// Homebrew always uses a Cellar directory — this is a design invariant.
	if strings.Contains(p, "/Cellar/") || strings.Contains(p, "/homebrew/") {
		return "brew upgrade belt"
	}

	// Scoop default path, but users can customize — verify scoop actually
	// manages belt by asking it.
	if strings.Contains(p, "/scoop/apps/") {
		return "scoop update belt"
	}

	// Path didn't match — ask package managers directly as a fallback.
	// exec.LookPath is cheap; the actual query only runs if the PM exists.
	if _, err := exec.LookPath("brew"); err == nil {
		if out, err := exec.Command("brew", "list", "belt").Output(); err == nil && len(out) > 0 {
			return "brew upgrade belt"
		}
	}
	if _, err := exec.LookPath("scoop"); err == nil {
		if out, err := exec.Command("scoop", "info", "belt").Output(); err == nil && len(out) > 0 {
			return "scoop update belt"
		}
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
		cfg.execFn = reexec
	}
	if cfg.selfPath == nil {
		cfg.selfPath = resolveSelfPath
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
// so callers treat it as "no prior check".
func readState(path string) (*state, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, nil // treat corrupt state as "no prior check"
	}
	return &s, nil
}

// writeState persists the timestamp file. Best-effort — errors are ignored by
// the caller since missing state just means "check again next time".
func writeState(path string, s *state) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// resolveSelfPath returns the canonical path of the currently running binary,
// following symlinks so a Homebrew-installed CLI updates the real file, not
// the symlink in /opt/homebrew/bin.
func resolveSelfPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
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
