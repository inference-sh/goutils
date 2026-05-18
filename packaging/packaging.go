package packaging

import (
	"archive/tar"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func TarDir(dir string) (string, error) {
	tarPath := dir + ".tar"
	tarFile, err := os.Create(tarPath)
	if err != nil {
		return "", fmt.Errorf("failed to create tar file: %w", err)
	}
	defer tarFile.Close()

	tw := tar.NewWriter(tarFile)
	defer tw.Close()

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the directory itself
		if path == dir {
			return nil
		}

		// Create a header based on the file info
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return fmt.Errorf("failed to create tar header: %w", err)
		}

		// Set the name to be relative to the directory
		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}
		header.Name = relPath

		// Write the header
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header: %w", err)
		}

		// If it's a regular file, write the content
		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("failed to open file: %w", err)
			}
			defer file.Close()

			if _, err := io.Copy(tw, file); err != nil {
				return fmt.Errorf("failed to write file content to tar: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to archive directory: %w", err)
	}

	return tarPath, nil
}

func ExtractEmbeddedDir(fsys embed.FS, srcPath, destPath string) error {
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list embedded files: %w", err)
	}

	return fs.WalkDir(fsys, srcPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Calculate relative path from the source directory
		relPath, err := filepath.Rel(srcPath, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		// Skip the root directory
		if relPath == "." {
			return nil
		}

		// Create the destination path
		destFilePath := filepath.Join(destPath, relPath)

		if d.IsDir() {
			return os.MkdirAll(destFilePath, 0755)
		}

		// If it's a file, copy its contents
		data, err := fsys.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read embedded file %s: %w", path, err)
		}

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(destFilePath), 0755); err != nil {
			return fmt.Errorf("failed to create parent directory for %s: %w", destFilePath, err)
		}

		// Write the file
		err = os.WriteFile(destFilePath, data, 0644)
		if err != nil {
			return fmt.Errorf("failed to write file %s: %w", destFilePath, err)
		}

		// Verify file was written
		if _, err := os.Stat(destFilePath); err != nil {
			return fmt.Errorf("failed to verify file was written: %w", err)
		}

		return nil
	})
}
