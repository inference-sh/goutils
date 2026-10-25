package autoupdate

import (
	"context"
	"errors"
	"fmt"

	"github.com/inference-sh/goutils/updater"
)

// ErrDevBuild is Prepare's answer for a binary that is not a release: a
// local build would be replaced by whatever was last published.
var ErrDevBuild = errors.New("this is a development build")

// ErrManaged is Prepare's answer for a binary a package manager installed.
// Replacing it would leave the manager's records wrong, so the update goes
// through the manager.
type ErrManaged struct {
	// Cmd updates the binary through its manager, e.g. "brew upgrade belt".
	Cmd string
}

func (e *ErrManaged) Error() string {
	return "installed by a package manager; update with '" + e.Cmd + "'"
}

// Plan is what replacing this binary with the latest release would do,
// worked out without changing anything. A caller that has to say what will
// happen before it happens (a daemon answering a remote update request)
// checks with Prepare and installs exactly that plan later.
type Plan struct {
	From string
	To   string
	// UpdateAvailable is false when From is already the latest release.
	UpdateAvailable bool
	// SelfPath is the binary the install replaces, symlinks resolved. A
	// restart runs this path.
	SelfPath string

	info *updater.UpdateInfo
	cfg  Config
}

// Prepare reads the release manifest and checks that this install can
// replace itself. It fails with ErrDevBuild, *ErrManaged or *ErrNotWritable
// when the binary cannot update itself, whatever the manifest says, and with
// a wrapped error when the manifest cannot be read. It ignores DisabledEnv,
// CheckInterval and the failed-install backoff: those pace automatic
// updates, and Prepare is for one that was asked for.
func Prepare(cfg Config) (*Plan, error) {
	applyDefaults(&cfg)
	if !cfg.Force && isDevVersion(cfg.CurrentVersion) {
		return nil, ErrDevBuild
	}
	selfPath, err := cfg.selfPath()
	if err != nil {
		return nil, fmt.Errorf("locate current binary: %w", err)
	}
	if cmd := packageManagerUpdateCmd(selfPath); cmd != "" {
		return nil, &ErrManaged{Cmd: cmd}
	}
	info, err := updater.CheckVersion(cfg.ManifestURL, cfg.Platform, cfg.Arch, cfg.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("check manifest: %w", err)
	}
	p := &Plan{
		From:            cfg.CurrentVersion,
		To:              info.AvailableVersion,
		UpdateAvailable: info.UpdateAvailable,
		SelfPath:        selfPath,
		info:            info,
		cfg:             cfg,
	}
	if !p.UpdateAvailable {
		return p, nil
	}
	if err := checkWritable(selfPath); err != nil {
		return nil, err
	}
	return p, nil
}

// Install downloads the planned release, checks its digest and swaps it in
// at SelfPath. The running process keeps running the old code; restarting
// is the caller's, since only it knows how it was started.
func (p *Plan) Install(ctx context.Context) error {
	if !p.UpdateAvailable {
		return nil
	}
	if err := installOverSelf(ctx, p.SelfPath, p.info, p.cfg); err != nil {
		return fmt.Errorf("install %s: %w", p.To, err)
	}
	return nil
}
