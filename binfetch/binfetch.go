package binfetch

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"inference.sh/goutils/progress"
)

// BinFetchOptions controls DownloadAndInstallBinary.
type BinFetchOptions struct {
	// URL to download the archive from (tar.gz, tgz, or zip).
	URL string
	// ExpectedSHA256 is the hex-encoded SHA256 of the downloaded archive.
	// If empty, checksum verification is skipped.
	ExpectedSHA256 string
	// DestPath is the final path for the extracted binary.
	// The containing directory is created if missing.
	DestPath string
	// Windows controls executable bit handling during extraction/install.
	// Set this based on the target platform, not the host.
	Windows bool
	// HTTPClient overrides the default http.Client.
	HTTPClient *http.Client
	// OnProgress is an optional callback invoked during the download with
	// bytes-received and total-bytes (from Content-Length, or 0 if unknown).
	OnProgress func(current, total int64)
	// Aliases is an optional list of symlink names to create alongside
	// DestPath. Each entry becomes filepath.Join(filepath.Dir(DestPath), name)
	// pointing at DestPath. Existing files at those paths are replaced.
	// Ignored on Windows where symlinks require elevated privileges.
	Aliases []string
}

// DownloadAndInstallBinary downloads an archive, verifies its SHA256, extracts
// the first regular file into a staging path next to DestPath, then atomically
// swaps it into place. Callers should already know which archive format the URL
// points at (.tar.gz / .tgz / .zip); other extensions default to tar.gz.
//
// This is the shared helper used by launcher's UpdateManager and the CLI's
// enginebin resolver. Keep it dependency-free so both can import it.
func DownloadAndInstallBinary(ctx context.Context, opts BinFetchOptions) error {
	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}

	tmpFile, err := downloadArchive(ctx, opts.URL, opts.ExpectedSHA256, opts.HTTPClient, opts.OnProgress)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if err := os.MkdirAll(filepath.Dir(opts.DestPath), 0o755); err != nil {
		return fmt.Errorf("create dest dir: %w", err)
	}

	stagingPath := opts.DestPath + ".new"
	if err := extractSingleBinary(tmpFile, opts.URL, stagingPath, opts.Windows); err != nil {
		return err
	}

	if _, err := os.Stat(opts.DestPath); err == nil {
		if err := os.Remove(opts.DestPath); err != nil {
			return fmt.Errorf("remove old binary: %w", err)
		}
	}
	if err := os.Rename(stagingPath, opts.DestPath); err != nil {
		return fmt.Errorf("install new binary: %w", err)
	}
	if !opts.Windows {
		if err := os.Chmod(opts.DestPath, 0o755); err != nil {
			return fmt.Errorf("chmod binary: %w", err)
		}
	}

	if !opts.Windows {
		if err := ensureAliases(opts.DestPath, opts.Aliases); err != nil {
			return fmt.Errorf("install aliases: %w", err)
		}
	}
	return nil
}

// ensureAliases creates a symlink in the same directory as destPath for each
// alias name pointing at destPath. Existing files at those paths are replaced.
// A no-op when aliases is empty.
func ensureAliases(destPath string, aliases []string) error {
	if len(aliases) == 0 {
		return nil
	}
	dir := filepath.Dir(destPath)
	target := filepath.Base(destPath)
	for _, alias := range aliases {
		if alias == "" || alias == target {
			continue
		}
		linkPath := filepath.Join(dir, alias)
		// Best-effort cleanup of any existing entry. Skip if it's already
		// a symlink pointing at the right place.
		if cur, err := os.Readlink(linkPath); err == nil && cur == target {
			continue
		}
		if err := os.Remove(linkPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove existing alias %s: %w", linkPath, err)
		}
		if err := os.Symlink(target, linkPath); err != nil {
			return fmt.Errorf("symlink %s -> %s: %w", linkPath, target, err)
		}
	}
	return nil
}

// downloadArchive fetches url to a temp file and verifies SHA256 (when provided).
// Caller is responsible for closing and removing the returned file.
func downloadArchive(ctx context.Context, url, expectedSHA256 string, client *http.Client, onProgress func(current, total int64)) (*os.File, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: unexpected status %s", resp.Status)
	}

	tmpFile, err := os.CreateTemp("", "binfetch-*"+archiveSuffix(url))
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}

	var src io.Reader = resp.Body
	if onProgress != nil {
		src = &progress.ProgressReader{
			Reader:     resp.Body,
			Total:      resp.ContentLength,
			OnProgress: onProgress,
		}
	}

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmpFile, hasher), src); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("save download: %w", err)
	}

	if expectedSHA256 != "" {
		got := hex.EncodeToString(hasher.Sum(nil))
		if got != expectedSHA256 {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return nil, fmt.Errorf("checksum mismatch: expected %s, got %s", expectedSHA256, got)
		}
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("rewind temp file: %w", err)
	}
	return tmpFile, nil
}

// extractSingleBinary extracts the first regular file from the archive into destPath.
// This matches the existing launcher semantics: one-file-per-archive, drop the rest.
func extractSingleBinary(archive *os.File, sourceURL, destPath string, windows bool) error {
	switch archiveSuffix(sourceURL) {
	case ".zip":
		return extractZipFirstFile(archive, destPath, windows)
	case ".tar.gz", ".tgz":
		return extractTarGzFirstFile(archive, destPath, windows)
	default:
		return fmt.Errorf("unsupported archive format for %s", sourceURL)
	}
}

func archiveSuffix(url string) string {
	switch {
	case strings.HasSuffix(url, ".tar.gz"):
		return ".tar.gz"
	case strings.HasSuffix(url, ".tgz"):
		return ".tgz"
	case strings.HasSuffix(url, ".zip"):
		return ".zip"
	default:
		return ".tar.gz"
	}
}

func extractTarGzFirstFile(src *os.File, destPath string, windows bool) error {
	gzr, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("no regular file found in archive")
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		return writeBinary(tr, destPath, windows)
	}
}

func extractZipFirstFile(src *os.File, destPath string, windows bool) error {
	info, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	zr, err := zip.NewReader(src, info.Size())
	if err != nil {
		return fmt.Errorf("zip reader: %w", err)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip entry: %w", err)
		}
		err = writeBinary(rc, destPath, windows)
		rc.Close()
		return err
	}
	return fmt.Errorf("no regular file found in archive")
}

func writeBinary(r io.Reader, destPath string, windows bool) error {
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create dest: %w", err)
	}
	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		return fmt.Errorf("write dest: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close dest: %w", err)
	}
	if !windows {
		if err := os.Chmod(destPath, 0o755); err != nil {
			return fmt.Errorf("chmod: %w", err)
		}
	}
	return nil
}
