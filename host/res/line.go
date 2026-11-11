package res

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Line is a line in a text file (fstab, mdadm.conf): the first line equal
// to it or matching Replace becomes it, the other such lines go, and a
// file with none gets it appended. The rest of the file is kept as it is.
// The file is replaced atomically, with its mode and owner (a new one:
// 0644, the writer's); a link is followed, so the file it names is the one
// written, and a link to nothing is an error.
type Line struct {
	Path string
	Line string
	// Replace matches the lines Line stands in for (an older entry for the
	// same mount point); nil: only lines equal to Line.
	Replace *regexp.Regexp
}

func (l *Line) ID() string { return "line in " + l.Path + ": " + l.Line }

// lineEdit is what Line.Check found: the file to write (links followed)
// and the content it gets.
type lineEdit struct {
	path string
	want []byte
}

func (l *Line) Check(context.Context) (State, error) {
	path, cur, want, err := l.read()
	switch {
	case err != nil:
		return State{}, err
	case cur == nil:
		return driftData(lineEdit{path, want}, "create the file with the line")
	case !bytes.Equal(cur, want):
		return driftData(lineEdit{path, want}, "%s", lineDrift(cur, l.Line))
	}
	return inPlace()
}

func (l *Line) Apply(_ context.Context, st State) (Result, error) {
	e := st.Data.(lineEdit)
	fi, err := os.Stat(e.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Result{}, err
	}
	mode, owner := attrs{}.forNew(fi, 0o644)
	if err := writeAtomic(e.path, bytes.NewReader(e.want), mode, owner); err != nil {
		return Result{}, err
	}
	return changed("%s", st.Drift)
}

// read is the path to write (links followed), the file's content (nil
// when there is no file) and the content it should have.
func (l *Line) read() (path string, cur, want []byte, err error) {
	path = l.Path
	if fi, err := os.Lstat(l.Path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		if path, err = filepath.EvalSymlinks(l.Path); err != nil {
			return "", nil, nil, fmt.Errorf("%s is a link to nothing: %w", l.Path, err)
		}
	}
	cur, err = os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return path, nil, WithLine(nil, l.Line, l.Replace), nil
	}
	if err != nil {
		return "", nil, nil, err
	}
	if cur == nil {
		cur = []byte{}
	}
	return path, cur, WithLine(cur, l.Line, l.Replace), nil
}

// WithLine is content with line in it, as Line puts it there: the first
// line equal to line or matching replace becomes line, the other such
// lines are dropped, and content with none gets line appended.
func WithLine(content []byte, line string, replace *regexp.Regexp) []byte {
	var out []string
	done := false
	text := string(content)
	trailing := strings.HasSuffix(text, "\n")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if text == "" {
		lines = nil
	}
	for _, s := range lines {
		if s == line || (replace != nil && replace.MatchString(s)) {
			if !done {
				out = append(out, line)
				done = true
			}
			continue
		}
		out = append(out, s)
	}
	if !done {
		out = append(out, line)
		trailing = true
	}
	res := strings.Join(out, "\n")
	if trailing {
		res += "\n"
	}
	return []byte(res)
}

func lineDrift(cur []byte, line string) string {
	for _, s := range strings.Split(string(cur), "\n") {
		if s == line {
			return "drop the lines it replaces"
		}
	}
	return "set the line"
}
