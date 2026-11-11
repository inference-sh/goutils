// Package res puts a host in a described state with idempotent resources:
// a file with its content, mode and owner; a line in a file; apt packages
// and repos; systemd units; a user's groups; a download checked against
// its sha256; a command guarded by what it creates.
//
// Every resource reads the host first (Check) and changes it only when it
// is not in place yet (Apply, with what Check read), so running the same
// list twice changes nothing the second time. A Runner runs an ordered list of tasks, reports
// each as ok, changed, failed or ignored, and runs the handlers the
// changed tasks notified (a daemon-reload after a unit changed) once each.
// Lazy, Assert and Always fit what a play needs between resources: one
// made from what the host is when the play reaches it, a condition it
// stops at, a change made outside it.
//
// Commands run through an Exec, so tests stand a fake in for the host.
// The package keeps no global state: each resource is a value that holds
// what it acts on. Beyond the standard library it uses x/sys and
// goutils/fileutil.
//
// The resources are for Linux: apt, dpkg and systemd, numeric owners, and
// commands in process groups. The package builds elsewhere, where an owner
// is never read and setting one fails.
package res
