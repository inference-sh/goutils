//go:build !windows

package autoupdate

import (
	"os"
	"syscall"
)

// ownFile reports whether fi is this process's user's file and writable by
// no one else: not by its group, not by everyone.
func ownFile(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Geteuid() && fi.Mode().Perm()&0o022 == 0
}
