//go:build !windows

package autoupdate

import (
	"os"
	"syscall"
)

// reexec replaces the current process image with path, preserving argv and
// environment. On success this does not return.
func reexec(path string, args []string) error {
	return syscall.Exec(path, args, os.Environ())
}
