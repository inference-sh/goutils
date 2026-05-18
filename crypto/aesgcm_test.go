package crypto

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileEncryptionDecryption(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "crypto_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Test data
	originalContent := []byte("Hello, this is a test file content!")
	passphrase := "test-passphrase"

	// Create original file
	originalFile := filepath.Join(tempDir, "original.txt")
	err = os.WriteFile(originalFile, originalContent, 0644)
	assert.NoError(t, err)

	// Create encrypted file
	encryptedFile := filepath.Join(tempDir, "encrypted.txt")
	err = encryptFile(originalFile, encryptedFile, passphrase)
	assert.NoError(t, err)

	// Create decrypted file
	decryptedFile := filepath.Join(tempDir, "decrypted.txt")
	err = decryptFile(encryptedFile, decryptedFile, passphrase)
	assert.NoError(t, err)

	// Read and verify decrypted content
	decryptedContent, err := os.ReadFile(decryptedFile)
	assert.NoError(t, err)
	assert.Equal(t, originalContent, decryptedContent)

	// Test wrong passphrase
	wrongPassphrase := "wrong-passphrase"
	wrongDecryptedFile := filepath.Join(tempDir, "wrong_decrypted.txt")
	err = decryptFile(encryptedFile, wrongDecryptedFile, wrongPassphrase)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt")
}

func TestInMemoryEncryptionDecryption(t *testing.T) {
	data := []byte("Hello, this is test data!")
	passphrase := "test-passphrase"

	// Encrypt
	encrypted, err := EncryptBytes(data, passphrase)
	assert.NoError(t, err)
	assert.NotEqual(t, data, encrypted)

	// Decrypt
	decrypted, err := DecryptBytes(encrypted, passphrase)
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)

	// Test wrong passphrase
	_, err = DecryptBytes(encrypted, "wrong-passphrase")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt")
}

// TestStreamingEncryptionDecryption simulates the uploader's streaming behavior
func TestStreamingEncryptionDecryption(t *testing.T) {
	// Test data
	originalContent := []byte("Hello, this is a test file content!")
	passphrase := "test-passphrase"

	// Create a buffer to simulate the network stream
	var networkBuffer bytes.Buffer

	// Encrypt using a streaming approach (like in upload.go)
	encReader, err := NewEncryptReader(bytes.NewReader(originalContent), passphrase)
	assert.NoError(t, err)

	// Write to our simulated network buffer
	_, err = io.Copy(&networkBuffer, encReader)
	assert.NoError(t, err)

	// Now decrypt from the network buffer (like in download.go)
	decReader, err := NewDecryptReader(bytes.NewReader(networkBuffer.Bytes()), passphrase)
	assert.NoError(t, err)

	// Read the decrypted content
	decrypted, err := io.ReadAll(decReader)
	assert.NoError(t, err)

	// Verify the content matches
	assert.Equal(t, originalContent, decrypted)

	// Test with chunks to simulate network streaming
	chunkSize := 16 // Small chunk size to test streaming
	var streamBuffer bytes.Buffer
	reader := bytes.NewReader(networkBuffer.Bytes())

	// Read and write in chunks
	chunk := make([]byte, chunkSize)
	for {
		n, err := reader.Read(chunk)
		if err == io.EOF {
			break
		}
		assert.NoError(t, err)
		_, err = streamBuffer.Write(chunk[:n])
		assert.NoError(t, err)
	}

	// Decrypt from chunked stream
	decReader2, err := NewDecryptReader(bytes.NewReader(streamBuffer.Bytes()), passphrase)
	assert.NoError(t, err)

	// Read the decrypted content
	decrypted2, err := io.ReadAll(decReader2)
	assert.NoError(t, err)

	// Verify the content matches
	assert.Equal(t, originalContent, decrypted2)
}

// Helper function to encrypt a file
func encryptFile(srcPath, destPath, passphrase string) error {
	// Open source file
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	// Create destination file
	dest, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer dest.Close()

	// Create encrypted reader
	encReader, err := NewEncryptReader(src, passphrase)
	if err != nil {
		return err
	}

	// Copy encrypted content
	_, err = io.Copy(dest, encReader)
	return err
}

// Helper function to decrypt a file
func decryptFile(srcPath, destPath, passphrase string) error {
	// Read encrypted file
	encryptedData, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}

	// Create decryption reader
	decReader, err := NewDecryptReader(bytes.NewReader(encryptedData), passphrase)
	if err != nil {
		return err
	}

	// Create destination file
	dest, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer dest.Close()

	// Copy decrypted content
	_, err = io.Copy(dest, decReader)
	return err
}
