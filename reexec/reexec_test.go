package reexec

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestMain runs the test binary as the helper when REEXEC_HELPER is set:
// "before" prints its pid and args and calls Exec on its own binary as
// "after", which prints the same and exits with status 3.
func TestMain(m *testing.M) {
	switch os.Getenv("REEXEC_HELPER") {
	case "before":
		fmt.Printf("before %d %s\n", os.Getpid(), strings.Join(os.Args[1:], ","))
		self, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Setenv("REEXEC_HELPER", "after")
		err = Exec(self, os.Args)
		fmt.Fprintln(os.Stderr, "Exec returned:", err)
		os.Exit(1)
	case "after":
		fmt.Printf("after %d %s\n", os.Getpid(), strings.Join(os.Args[1:], ","))
		os.Exit(3)
	}
	os.Exit(m.Run())
}

// The new code runs with the same args and environment, its output lands
// where the caller's did, and its status is the process's status.
func TestExec(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "one", "two")
	cmd.Env = append(os.Environ(), "REEXEC_HELPER=before")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatalf("err = %v, want exit status 3; stdout %q stderr %q", err, out, stderr.String())
	}

	var before, after struct {
		pid  int
		args string
	}
	if _, err := fmt.Sscanf(string(out), "before %d %s\nafter %d %s\n", &before.pid, &before.args, &after.pid, &after.args); err != nil {
		t.Fatalf("output %q: %v", out, err)
	}
	if before.args != "one,two" || after.args != "one,two" {
		t.Fatalf("args before %q after %q, want one,two for both", before.args, after.args)
	}
	if runtime.GOOS != "windows" && before.pid != after.pid {
		t.Fatalf("pid %d became %d; Unix replaces the image in place", before.pid, after.pid)
	}
}

// A binary that cannot be started leaves the caller running with the error.
func TestExecMissingBinary(t *testing.T) {
	err := Exec(filepath.Join(t.TempDir(), "missing"), []string{"missing"})
	if err == nil {
		t.Fatal("Exec of a missing binary returned nil")
	}
}
