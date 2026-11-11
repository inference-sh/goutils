package res

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
)

// Resource is one piece of host state, or one action.
//
// A state (File, Line, Service, an Apt package) is in place or not: Check
// reads the host, and Apply acts on what that Check found. An action
// (Restart, DaemonReload, Always, a Command without a guard) has no state
// to read: its Check always reports drift and its Apply always acts. An
// action is a handler, or a task meant to run every time.
type Resource interface {
	// ID names the resource and what it puts in place ("file /etc/fstab").
	ID() string
	// Check reads the host and reports whether the resource is in place.
	// It changes nothing.
	Check(ctx context.Context) (State, error)
	// Apply puts the resource in place. The Runner calls it right after
	// Check, with what Check found, and only when that was not in place.
	// It reports Changed with what it did; a failure is the error.
	Apply(ctx context.Context, st State) (Result, error)
}

// State is what Check found.
type State struct {
	InPlace bool
	// Drift is what Apply would change, when not in place ("mode 0644,
	// want 0600"). It never holds a file's content.
	Drift string
	// Data is what Check read that its Apply acts on (the packages
	// missing, the key fetched), for that resource alone: the Runner hands
	// it on untouched.
	Data any
}

func inPlace() (State, error)                 { return State{InPlace: true}, nil }
func drift(f string, a ...any) (State, error) { return State{Drift: fmt.Sprintf(f, a...)}, nil }

// driftData is drift with what Apply acts on.
func driftData(data any, f string, a ...any) (State, error) {
	return State{Drift: fmt.Sprintf(f, a...), Data: data}, nil
}
func changed(f string, a ...any) (Result, error) {
	return Result{Status: Changed, Msg: fmt.Sprintf(f, a...)}, nil
}
func unchanged(msg string) (Result, error) { return Result{Status: OK, Msg: msg}, nil }

// Status is how a task ended.
type Status int

const (
	OK Status = iota // in place already, nothing changed
	Changed
	Failed
	Ignored // failed, and the play went on (Task.IgnoreErrors)
)

func (s Status) String() string {
	switch s {
	case OK:
		return "ok"
	case Changed:
		return "changed"
	case Failed:
		return "failed"
	case Ignored:
		return "ignored"
	}
	return fmt.Sprintf("Status(%d)", int(s))
}

// Result is one task's outcome, for the report.
type Result struct {
	Name    string // the task's name, or the resource's ID
	Status  Status
	Msg     string // what Apply did, else what Check found would change
	Err     error  // set when Failed or Ignored
	Handler bool   // a handler, run because a task notified it
}

// Task is a resource in a play.
type Task struct {
	// Name is the task's line in the report; "" uses the resource's ID.
	Name     string
	Resource Resource
	// Notify are the handlers to run when the task changed something.
	Notify []*Handler
	// IgnoreErrors: a failure is reported Ignored and the play goes on.
	IgnoreErrors bool

	flush bool
}

// Flush is a task that runs the handlers notified so far, there in the
// play instead of at its end: a unit written, then daemon-reload and a
// restart, then the unit enabled and started.
func Flush() Task { return Task{Name: "flush handlers", flush: true} }

// Handler is a resource that runs only when a task notified it, once,
// however many did.
type Handler struct {
	Name     string
	Resource Resource
}

// Play is an ordered list of tasks and the handlers they may notify.
// Notified handlers run in the order Handlers lists them; one a task
// notifies that Handlers leaves out runs after those, in the order first
// notified.
type Play struct {
	Tasks    []Task
	Handlers []*Handler
}

// Runner runs plays.
type Runner struct {
	// OnStart, when set, gets each task's and handler's name as it starts.
	OnStart func(name string)
	// OnProgress, when set, gets what a long task says it has done so far
	// (Progress), for the line that follows it.
	OnProgress func(detail string)
	// OnResult, when set, gets each task's and handler's result as it
	// lands.
	OnResult func(Result)
}

type progressKey struct{}

// Progress tells the Runner's OnProgress how far a long Check or Apply
// is ("1,240,000 files, 85,000/s"). It does nothing when no one listens.
func Progress(ctx context.Context, format string, a ...any) {
	if f, ok := ctx.Value(progressKey{}).(func(string)); ok {
		f(fmt.Sprintf(format, a...))
	}
}

// Run runs p's tasks in order. It stops at the first failure, and returns
// it as the error. The handlers notified before the failure still run
// (Ansible's force_handlers): a unit written is reloaded, and a service
// whose binary was replaced restarts on it.
func (r *Runner) Run(ctx context.Context, p Play) error {
	for _, t := range p.Tasks {
		if t.Resource == nil && !t.flush {
			return fmt.Errorf("task %q has no resource", t.Name)
		}
		for _, h := range t.Notify {
			if h == nil || h.Resource == nil {
				return fmt.Errorf("task %q notifies a handler with no resource", t.name())
			}
		}
	}
	start := func(name string) string {
		if r.OnStart != nil {
			r.OnStart(name)
		}
		return name
	}
	report := func(res Result) Result {
		if r.OnResult != nil {
			r.OnResult(res)
		}
		return res
	}
	var notified []*Handler // in the order first notified
	flush := func() error {
		var order []*Handler
		for _, h := range slices.Concat(p.Handlers, notified) {
			if slices.Contains(notified, h) && !slices.Contains(order, h) {
				order = append(order, h)
			}
		}
		notified = nil
		var errs []error
		for _, h := range order {
			res := r.one(ctx, start(cmp.Or(h.Name, h.Resource.ID())), h.Resource)
			res.Handler = true
			if report(res).Status == Failed {
				errs = append(errs, fmt.Errorf("handler %q: %w", h.Name, res.Err))
			}
		}
		return errors.Join(errs...)
	}

	for _, t := range p.Tasks {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, flush())
		}
		if t.flush {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		res := r.one(ctx, start(t.name()), t.Resource)
		if res.Status == Failed && t.IgnoreErrors {
			res.Status = Ignored
		}
		switch report(res).Status {
		case Failed:
			return errors.Join(fmt.Errorf("%s: %w", res.Name, res.Err), flush())
		case Changed:
			for _, h := range t.Notify {
				if !slices.Contains(notified, h) {
					notified = append(notified, h)
				}
			}
		}
	}
	return flush()
}

// one checks rc and applies it, with what the check found, when it is not
// in place.
func (r *Runner) one(ctx context.Context, name string, rc Resource) Result {
	res := Result{Name: name}
	if r.OnProgress != nil {
		ctx = context.WithValue(ctx, progressKey{}, r.OnProgress)
	}
	fail := func(err error) Result {
		res.Status, res.Err, res.Msg = Failed, err, err.Error()
		return res
	}
	st, err := rc.Check(ctx)
	if err != nil {
		return fail(err)
	}
	if st.InPlace {
		res.Status = OK
		return res
	}
	got, err := rc.Apply(ctx, st)
	if err != nil {
		return fail(err)
	}
	res.Status, res.Msg = got.Status, cmp.Or(got.Msg, st.Drift)
	return res
}

func (t Task) name() string {
	if t.Name != "" {
		return t.Name
	}
	if t.Resource != nil {
		return t.Resource.ID()
	}
	return ""
}

// All is many resources as one task, for a tree of them (a directory's
// copy) whose parts are not worth a line each. Check reads every part;
// Apply puts in place, in order, those that were not, and says how many.
type All struct {
	// What names them ("the engine data").
	What  string
	Parts []Resource
}

func (a *All) ID() string { return "all of " + a.What }

// allPart is a part not in place, with what its Check found.
type allPart struct {
	r  Resource
	st State
}

func (a *All) Check(ctx context.Context) (State, error) {
	var d []allPart
	for _, p := range a.Parts {
		st, err := p.Check(ctx)
		if err != nil {
			return State{}, fmt.Errorf("%s: %w", p.ID(), err)
		}
		if !st.InPlace {
			d = append(d, allPart{p, st})
		}
	}
	if len(d) == 0 {
		return inPlace()
	}
	return driftData(d, "%d of %d to put in place", len(d), len(a.Parts))
}

func (a *All) Apply(ctx context.Context, st State) (Result, error) {
	d, _ := st.Data.([]allPart)
	n := 0
	for _, p := range d {
		r, err := p.r.Apply(ctx, p.st)
		if err != nil {
			return Result{}, fmt.Errorf("%s: %w", p.r.ID(), err)
		}
		if r.Status == Changed {
			n++
		}
	}
	return changed("%s (%d of %d files and dirs)", a.What, n, len(a.Parts))
}
