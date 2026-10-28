//go:build windows

package autoupdate

import "os"

// ownFile is true on Windows: the state lives in the user's profile, whose
// ACL keeps other users out.
func ownFile(os.FileInfo) bool { return true }
