package packaging

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Default limits for ExtractZip. They bound what an archive can make the
// caller write; a real app source tree is far below both.
const (
	DefaultMaxZipEntries       = 200_000
	DefaultMaxZipBytes   int64 = 8 << 30 // uncompressed bytes, all entries
)

// ExtractOptions configures ExtractZip. The zero value applies the default
// limits and skips symlink entries.
type ExtractOptions struct {
	// MaxEntries caps the number of entries (0: DefaultMaxZipEntries).
	MaxEntries int
	// MaxBytes caps the uncompressed bytes written, counted from the
	// decompressed streams; header sizes are not trusted (0: DefaultMaxZipBytes).
	MaxBytes int64
	// KeepSymlinks creates the archive's symlink entries instead of skipping
	// them. Targets must be relative, no entry may sit at or below a symlink
	// entry, and after extraction every created link must resolve inside the
	// destination; a link that dangles or escapes is removed and extraction
	// fails. Links already in the destination are not touched.
	KeepSymlinks bool
	// OnSkip, if set, is called for each entry that is not extracted
	// (special files, and symlinks unless KeepSymlinks).
	OnSkip func(name string, mode fs.FileMode)
}

// ExtractZip extracts the archive at zipPath into the existing directory dir.
//
// Every write goes through an os.Root at dir, so no entry (or a symlink one
// creates) can reach outside it. File modes keep only rwx bits without
// group/other write, and owner read/write is always set.
func ExtractZip(zipPath, dir string, opt ExtractOptions) error {
	if opt.MaxEntries <= 0 {
		opt.MaxEntries = DefaultMaxZipEntries
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = DefaultMaxZipBytes
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
	}
	defer zr.Close()

	if len(zr.File) > opt.MaxEntries {
		return fmt.Errorf("zip has %d entries, more than the limit of %d", len(zr.File), opt.MaxEntries)
	}

	var links []string
	if opt.KeepSymlinks {
		if links, err = archiveSymlinks(zr.File); err != nil {
			return err
		}
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("failed to open destination directory: %w", err)
	}
	defer root.Close()

	remaining := opt.MaxBytes
	for _, file := range zr.File {
		// Zip slip: reject absolute paths and entries that walk above the
		// destination (e.g. "../evil"). os.Root enforces the same below.
		if !filepath.IsLocal(file.Name) {
			return fmt.Errorf("invalid file path in zip: %q", file.Name)
		}
		name := filepath.FromSlash(file.Name)
		mode := file.Mode()

		switch {
		case mode.IsDir():
			if err := root.MkdirAll(name, 0o755); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		case mode&fs.ModeSymlink != 0 && opt.KeepSymlinks:
			if err := extractSymlink(root, name, file); err != nil {
				return err
			}
			continue
		case !mode.IsRegular():
			if opt.OnSkip != nil {
				opt.OnSkip(file.Name, mode.Type())
			}
			continue
		}

		if d := filepath.Dir(name); d != "." {
			if err := root.MkdirAll(d, 0o755); err != nil {
				return fmt.Errorf("failed to create directory structure: %w", err)
			}
		}
		perm := mode.Perm() & 0o755
		perm |= 0o600
		n, err := extractEntry(root, name, file, perm, remaining)
		if err != nil {
			if errors.Is(err, errTooLarge) {
				return fmt.Errorf("zip expands to more than %d bytes", opt.MaxBytes)
			}
			return err
		}
		remaining -= n
	}

	return checkLinks(root, links)
}

var errTooLarge = errors.New("zip entry over the size limit")

// extractEntry writes one regular entry, failing once more than limit bytes
// come out of it.
func extractEntry(root *os.Root, name string, file *zip.File, perm os.FileMode, limit int64) (int64, error) {
	dst, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return 0, fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dst.Close()

	src, err := file.Open()
	if err != nil {
		return 0, fmt.Errorf("failed to open file in zip: %w", err)
	}
	defer src.Close()

	n, err := io.Copy(dst, io.LimitReader(src, limit+1))
	if err != nil {
		return n, fmt.Errorf("failed to extract file: %w", err)
	}
	if n > limit {
		return n, errTooLarge
	}
	// OpenFile applies the umask, and an existing file keeps its mode; set
	// the intended mode explicitly.
	if err := dst.Chmod(perm); err != nil {
		return n, fmt.Errorf("failed to set file mode: %w", err)
	}
	return n, dst.Close()
}

// extractSymlink creates a symlink entry, replacing a non-directory already
// at its name (a re-extraction over an earlier tree).
func extractSymlink(root *os.Root, name string, file *zip.File) error {
	target, err := readLinkTarget(file)
	if err != nil {
		return err
	}
	if d := filepath.Dir(name); d != "." {
		if err := root.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("failed to create directory structure: %w", err)
		}
	}
	err = root.Symlink(target, name)
	if errors.Is(err, fs.ErrExist) {
		if fi, lerr := root.Lstat(name); lerr == nil && !fi.IsDir() {
			if err = root.Remove(name); err == nil {
				err = root.Symlink(target, name)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("failed to create symlink %s: %w", file.Name, err)
	}
	return nil
}

func readLinkTarget(f *zip.File) (string, error) {
	r, err := f.Open()
	if err != nil {
		return "", fmt.Errorf("read symlink %s: %w", f.Name, err)
	}
	defer r.Close()
	target, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		return "", fmt.Errorf("read symlink %s: %w", f.Name, err)
	}
	return string(target), nil
}

// archiveSymlinks returns the names of the archive's symlink entries, and
// refuses archives where another entry goes through a symlink or a symlink
// target is absolute.
func archiveSymlinks(files []*zip.File) ([]string, error) {
	var links []string
	isLink := map[string]bool{}
	for _, f := range files {
		if f.Mode()&fs.ModeSymlink == 0 {
			continue
		}
		name := path.Clean(strings.TrimSuffix(f.Name, "/"))
		if isLink[name] {
			return nil, fmt.Errorf("archive has duplicate symlink entry %s", f.Name)
		}
		isLink[name] = true
		links = append(links, name)

		t, err := readLinkTarget(f)
		if err != nil {
			return nil, err
		}
		if path.IsAbs(t) || filepath.IsAbs(t) || filepath.VolumeName(t) != "" || strings.HasPrefix(t, `\`) {
			return nil, fmt.Errorf("archive symlink %s has absolute target %q", f.Name, t)
		}
	}
	if len(isLink) == 0 {
		return nil, nil
	}
	for _, f := range files {
		name := path.Clean(strings.TrimSuffix(f.Name, "/"))
		self := f.Mode()&fs.ModeSymlink != 0
		for p := name; p != "." && p != "/" && p != ""; p = path.Dir(p) {
			if p == name && self {
				continue
			}
			if isLink[p] {
				return nil, fmt.Errorf("archive entry %s goes through symlink %s", f.Name, p)
			}
		}
	}
	return links, nil
}

// checkLinks removes every archive symlink that does not resolve inside the
// root (it dangles or escapes) and fails if there was one. os.Root refuses
// to follow a link out of the root, so Stat failing is the test.
func checkLinks(root *os.Root, links []string) error {
	var bad []string
	for _, name := range links {
		p := filepath.FromSlash(name)
		if _, err := root.Stat(p); err == nil {
			continue
		}
		bad = append(bad, name)
		if err := root.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("archive contains symlinks that are dangling or point outside the destination: %s", strings.Join(bad, ", "))
	}
	return nil
}
