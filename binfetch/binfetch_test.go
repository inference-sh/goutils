package binfetch

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// binaryPayload is the content written into test archives, pretending to be a binary.
var binaryPayload = []byte("#!/usr/bin/env bash\necho hello from binfetch test\n")

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func makeTarGz(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o755,
		Size:     int64(len(payload)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar write header: %v", err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatalf("tar write body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	return buf.Bytes()
}

func makeZip(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// startArchiveServer serves a single archive at the path matching suffix.
// Returns the full URL.
func startArchiveServer(t *testing.T, archive []byte, suffix string) (string, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/binary"+suffix, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", itoa(len(archive)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(archive)
	})
	srv := httptest.NewServer(mux)
	return srv.URL + "/binary" + suffix, srv
}

func itoa(i int) string {
	// Small helper to avoid pulling strconv just for one call.
	b := []byte{}
	if i == 0 {
		return "0"
	}
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestDownloadAndInstallBinary_TarGzHappyPath(t *testing.T) {
	archive := makeTarGz(t, "engine", binaryPayload)
	url, srv := startArchiveServer(t, archive, ".tar.gz")
	defer srv.Close()

	tmp := t.TempDir()
	dest := filepath.Join(tmp, "bin", "engine")

	var progressCalled bool
	err := DownloadAndInstallBinary(context.Background(), BinFetchOptions{
		URL:            url,
		ExpectedSHA256: sha256Hex(archive),
		DestPath:       dest,
		Windows:        runtime.GOOS == "windows",
		OnProgress: func(current, total int64) {
			if current > 0 {
				progressCalled = true
			}
		},
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read installed: %v", err)
	}
	if !bytes.Equal(got, binaryPayload) {
		t.Fatalf("installed payload mismatch:\nwant %q\ngot  %q", binaryPayload, got)
	}
	if !progressCalled {
		t.Errorf("expected OnProgress callback to fire at least once")
	}
}

func TestDownloadAndInstallBinary_ZipHappyPath(t *testing.T) {
	archive := makeZip(t, "engine", binaryPayload)
	url, srv := startArchiveServer(t, archive, ".zip")
	defer srv.Close()

	tmp := t.TempDir()
	dest := filepath.Join(tmp, "bin", "engine")

	err := DownloadAndInstallBinary(context.Background(), BinFetchOptions{
		URL:            url,
		ExpectedSHA256: sha256Hex(archive),
		DestPath:       dest,
		Windows:        runtime.GOOS == "windows",
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read installed: %v", err)
	}
	if !bytes.Equal(got, binaryPayload) {
		t.Fatalf("installed payload mismatch")
	}
}

func TestDownloadAndInstallBinary_ChecksumMismatch(t *testing.T) {
	archive := makeTarGz(t, "engine", binaryPayload)
	url, srv := startArchiveServer(t, archive, ".tar.gz")
	defer srv.Close()

	tmp := t.TempDir()
	dest := filepath.Join(tmp, "bin", "engine")

	err := DownloadAndInstallBinary(context.Background(), BinFetchOptions{
		URL:            url,
		ExpectedSHA256: strings.Repeat("0", 64),
		DestPath:       dest,
	})
	if err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected 'checksum mismatch' in error, got: %v", err)
	}
	if _, statErr := os.Stat(dest); statErr == nil {
		t.Error("dest file should not exist after failed install")
	}
}

func TestDownloadAndInstallBinary_SkipChecksumWhenEmpty(t *testing.T) {
	archive := makeTarGz(t, "engine", binaryPayload)
	url, srv := startArchiveServer(t, archive, ".tar.gz")
	defer srv.Close()

	tmp := t.TempDir()
	dest := filepath.Join(tmp, "bin", "engine")

	err := DownloadAndInstallBinary(context.Background(), BinFetchOptions{
		URL:      url,
		DestPath: dest,
		// ExpectedSHA256 intentionally empty
	})
	if err != nil {
		t.Fatalf("install with empty checksum: %v", err)
	}
}

func TestDownloadAndInstallBinary_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	tmp := t.TempDir()
	dest := filepath.Join(tmp, "bin", "engine")

	err := DownloadAndInstallBinary(context.Background(), BinFetchOptions{
		URL:      srv.URL + "/binary.tar.gz",
		DestPath: dest,
	})
	if err == nil {
		t.Fatal("expected HTTP error, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected status") {
		t.Errorf("expected 'unexpected status' in error, got: %v", err)
	}
}

func TestDownloadAndInstallBinary_CreatesAliases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("aliases are no-ops on Windows")
	}
	archive := makeTarGz(t, "inferencesh", binaryPayload)
	url, srv := startArchiveServer(t, archive, ".tar.gz")
	defer srv.Close()

	tmp := t.TempDir()
	dest := filepath.Join(tmp, "bin", "inferencesh")

	err := DownloadAndInstallBinary(context.Background(), BinFetchOptions{
		URL:            url,
		ExpectedSHA256: sha256Hex(archive),
		DestPath:       dest,
		Aliases:        []string{"infsh", "inf"},
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	for _, alias := range []string{"infsh", "inf"} {
		linkPath := filepath.Join(filepath.Dir(dest), alias)
		target, err := os.Readlink(linkPath)
		if err != nil {
			t.Fatalf("readlink %s: %v", linkPath, err)
		}
		if target != "inferencesh" {
			t.Errorf("alias %s -> %s, want inferencesh", alias, target)
		}
	}
}

func TestDownloadAndInstallBinary_ReplacesStaleAlias(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("aliases are no-ops on Windows")
	}
	archive := makeTarGz(t, "inferencesh", binaryPayload)
	url, srv := startArchiveServer(t, archive, ".tar.gz")
	defer srv.Close()

	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Pre-create an alias pointing somewhere wrong.
	stalePath := filepath.Join(binDir, "infsh")
	if err := os.Symlink("/some/other/binary", stalePath); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(binDir, "inferencesh")
	err := DownloadAndInstallBinary(context.Background(), BinFetchOptions{
		URL:            url,
		ExpectedSHA256: sha256Hex(archive),
		DestPath:       dest,
		Aliases:        []string{"infsh"},
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	target, err := os.Readlink(stalePath)
	if err != nil {
		t.Fatal(err)
	}
	if target != "inferencesh" {
		t.Errorf("alias not updated: %s", target)
	}
}

func TestDownloadAndInstallBinary_ReplacesExisting(t *testing.T) {
	archive := makeTarGz(t, "engine", binaryPayload)
	url, srv := startArchiveServer(t, archive, ".tar.gz")
	defer srv.Close()

	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(binDir, "engine")
	if err := os.WriteFile(dest, []byte("stale content"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := DownloadAndInstallBinary(context.Background(), BinFetchOptions{
		URL:            url,
		ExpectedSHA256: sha256Hex(archive),
		DestPath:       dest,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read installed: %v", err)
	}
	if string(got) == "stale content" {
		t.Error("stale content was not replaced")
	}
	if !bytes.Equal(got, binaryPayload) {
		t.Fatalf("new payload mismatch")
	}
}
