//go:build unix

package fileutil

import (
	"os"
	"syscall"
)

// ownFile reports whether fi is this process's user's file and writable by
// no one else.
func ownFile(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid() && fi.Mode().Perm()&0o022 == 0
}
