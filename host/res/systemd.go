package res

import (
	"context"
	"slices"
	"strings"
	"time"
)

// systemctlTimeout bounds one systemctl call (a unit's start included).
const systemctlTimeout = 5 * time.Minute

func systemctl(args ...string) Cmd {
	return Cmd{Name: "systemctl", Args: args, Timeout: systemctlTimeout}
}

// Service is a systemd unit enabled at boot, running, or both. A field
// left false leaves that side of the unit as it is (it never disables or
// stops one).
type Service struct {
	Exec    Exec
	Name    string
	Enabled bool
	Running bool
}

func (s *Service) ID() string {
	var want []string
	if s.Enabled {
		want = append(want, "enabled")
	}
	if s.Running {
		want = append(want, "running")
	}
	return "service " + s.Name + " " + strings.Join(want, ", ")
}

// enabledStates are the UnitFileStates is-enabled exits 0 for: enabled,
// or a unit that cannot be (static, alias, indirect, generated).
var enabledStates = []string{"enabled", "enabled-runtime", "static", "alias", "indirect", "generated", "transient"}

// ShowProps is one unit's properties as systemctl show prints them
// (Key=Value lines).
func ShowProps(out string) map[string]string {
	kv := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			kv[k] = v
		}
	}
	return kv
}

// todo is what is not yet so, from one systemctl show: enable, start.
func (s *Service) todo(ctx context.Context) (enable, start bool, err error) {
	o, err := run(ctx, s.Exec, systemctl("show", "-p", "UnitFileState", "-p", "ActiveState", s.Name))
	if err != nil {
		return false, false, err
	}
	kv := ShowProps(o.Out)
	active := kv["ActiveState"] == "active" || kv["ActiveState"] == "reloading"
	return s.Enabled && !slices.Contains(enabledStates, kv["UnitFileState"]), s.Running && !active, nil
}

// Check's Data is the systemctl call that puts it in place.
func (s *Service) Check(ctx context.Context) (State, error) {
	enable, start, err := s.todo(ctx)
	switch {
	case err != nil:
		return State{}, err
	case enable && start:
		return driftData(systemctl("enable", "--now", s.Name), "enable and start")
	case enable:
		return driftData(systemctl("enable", s.Name), "enable")
	case start:
		return driftData(systemctl("start", s.Name), "start")
	}
	return inPlace()
}

func (s *Service) Apply(ctx context.Context, st State) (Result, error) {
	if _, err := run(ctx, s.Exec, st.Data.(Cmd)); err != nil {
		return Result{}, err
	}
	return changed("%s", st.Drift)
}

// Restart restarts a unit (or starts a stopped one). It is an action, for
// a handler: run because something the unit reads changed.
type Restart struct {
	Exec Exec
	Name string
}

func (r *Restart) ID() string                           { return "restart " + r.Name }
func (r *Restart) Check(context.Context) (State, error) { return drift("restart") }
func (r *Restart) Apply(ctx context.Context, _ State) (Result, error) {
	if _, err := run(ctx, r.Exec, systemctl("restart", r.Name)); err != nil {
		return Result{}, err
	}
	return changed("restarted")
}

// DaemonReload makes systemd read its units (and fstab's) again. It is an
// action, for a handler: run because a unit changed.
type DaemonReload struct {
	Exec Exec
}

func (d *DaemonReload) ID() string                           { return "systemd daemon-reload" }
func (d *DaemonReload) Check(context.Context) (State, error) { return drift("reload") }
func (d *DaemonReload) Apply(ctx context.Context, _ State) (Result, error) {
	if _, err := run(ctx, d.Exec, systemctl("daemon-reload")); err != nil {
		return Result{}, err
	}
	return changed("reloaded")
}
