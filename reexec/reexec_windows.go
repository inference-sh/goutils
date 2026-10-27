//go:build windows

package reexec

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
)

func execProcess(path string, args []string) error {
	cmd := exec.Command(path, args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		return err
	}
	signal.Ignore(os.Interrupt)
	err := cmd.Wait()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		os.Exit(exit.ExitCode())
	}
	if err != nil {
		// The child ran but its status is unknown.
		os.Exit(1)
	}
	os.Exit(0)
	return nil
}
