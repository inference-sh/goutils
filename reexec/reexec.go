// Package reexec runs a binary in place of the running process, with the
// same arguments and environment. A program that has just replaced its own
// binary calls it to start running the new code.
package reexec

// Exec runs path in place of this process with args (args[0] is the program
// name, as in os.Args) and this process's environment. It returns only when
// it fails.
//
// Unix replaces the process image. The pid stays, so a terminal's job
// control, a service manager's tracking and anything that recorded the pid
// carry over to the new code.
//
// Windows cannot replace a running image. Exec runs path as a child on this
// console with this process's stdio, waits for it, and exits with its
// status, so a terminal's prompt comes back only when the new code ends.
// Ctrl-C reaches every process on the console; from the call on, this one
// ignores it and leaves it to the child. The child has its own pid: a caller
// that recorded its pid or holds a lock releases them before calling Exec.
// Nothing this process still reads (stdin included) should be read after
// the call, since the child reads the same handles.
func Exec(path string, args []string) error {
	return execProcess(path, args)
}
