//go:build windows

package autoupdate

import (
	"os"
	"os/exec"
)

// reexec on Windows cannot replace the running process image. Instead it
// spawns the updated binary as a child, lets it inherit stdio, waits for it
// to finish, and exits with its exit code so the overall user experience is
// close to the Unix flow.
//
// Note: installOverSelf for Windows relies on the .old.exe rename dance
// handled inside common-go/pkg/utils.DownloadAndInstallBinary when Windows
// is true. See that function for details.
func reexec(path string, args []string) error {
	cmd := exec.Command(path, args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	os.Exit(0)
	return nil // unreachable
}
