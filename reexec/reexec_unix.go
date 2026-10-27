//go:build !windows

package reexec

import (
	"os"
	"syscall"
)

func execProcess(path string, args []string) error {
	return syscall.Exec(path, args, os.Environ())
}
