package fileutil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// WriteFileAtomic atomically replaces path with what r holds, with mode. It
// writes a new temp file in path's directory and renames it into place, so
// an existing file's looser mode is not kept and a symlink at path is
// replaced rather than followed. The data is synced before the rename, so
// after a crash path holds either the old content or all of the new.
func WriteFileAtomic(path string, r io.Reader, mode os.FileMode) error {
	return writeFileAtomic(path, r, mode, -1, -1)
}

// WriteFileAtomicOwned is WriteFileAtomic with the file owned by uid:gid
// from before it is in place (root writing a file for another user, or a
// root-owned one whatever the directory's group). Unix only: Chown fails
// on Windows.
func WriteFileAtomicOwned(path string, r io.Reader, mode os.FileMode, uid, gid int) error {
	return writeFileAtomic(path, r, mode, uid, gid)
}

func writeFileAtomic(path string, r io.Reader, mode os.FileMode, uid, gid int) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpPath)
		}
	}()
	// Chmod on the file, not the umask'd create mode.
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if uid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			tmp.Close()
			return err
		}
	}
	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	ok = true
	return nil
}
