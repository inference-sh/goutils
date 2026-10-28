// Package fileutil reads and writes files that another user must not be
// able to steer: state a process acts on, a root service among them.
package fileutil

import (
	"errors"
	"io"
	"os"
)

// ErrNotOwn is ReadOwnFile's refusal: the file is not a regular file, is
// another user's, or is writable by its group or by everyone.
var ErrNotOwn = errors.New("not this user's own file")

// ReadOwnFile reads path when only this process's user can have written it:
// a regular file it owns, not writable by its group or by everyone. A file
// another user planted is refused with ErrNotOwn.
func ReadOwnFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || !ownFile(fi) {
		return nil, ErrNotOwn
	}
	return io.ReadAll(f)
}
