// Package crypto provides encryption utilities for sensitive data
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// EncryptionPrefixV1 marks v1 encrypted values (direct encryption with KEK)
	EncryptionPrefixV1 = "enc:v1:"

	// EncryptionPrefixV2 marks v2 encrypted values (envelope encryption with DEK/KEK)
	// Format: enc:v2:<base64(encrypted_dek)>:<base64(encrypted_data)>
	EncryptionPrefixV2 = "enc:v2:"

	// EncryptionPrefix is the current version used for new encryptions
	EncryptionPrefix = EncryptionPrefixV2

	// PBKDF2 parameters (NIST recommendations)
	pbkdf2Iterations = 600000 // OWASP 2023 recommendation for SHA-256
	keyLength        = 32     // AES-256
	saltLength       = 16
	nonceLength      = 12 // GCM standard nonce size
	dekLength        = 32 // DEK is also AES-256
)

var (
	// ErrNoEncryptionKey is returned when encryption is required but no key is configured
	ErrNoEncryptionKey = errors.New("SECRETS_ENCRYPTION_KEY not configured")

	// ErrDecryptionFailed is returned when decryption fails
	ErrDecryptionFailed = errors.New("failed to decrypt secret")

	// ErrInvalidCiphertext is returned when ciphertext format is invalid
	ErrInvalidCiphertext = errors.New("invalid ciphertext format")

	// Cached derived keys (derived once at startup)
	derivedKey     []byte
	derivedKeyPrev []byte // Previous key for rotation
	derivedKeyOnce sync.Once
	derivedKeyErr  error

	// Fixed salt for deterministic key derivation
	// In production, you might want per-installation salt stored separately
	fixedSalt = []byte("inference.sh.secrets.v1.salt")
)

// SecretsEncryption provides encryption/decryption for secrets
type SecretsEncryption struct {
	key []byte
}

// NewSecretsEncryption creates a new encryption instance
// Returns nil if no encryption key is configured (encryption disabled)
func NewSecretsEncryption() (*SecretsEncryption, error) {
	key, err := getDerivedKey()
	if err != nil {
		if errors.Is(err, ErrNoEncryptionKey) {
			return nil, nil // Encryption disabled
		}
		return nil, err
	}
	return &SecretsEncryption{key: key}, nil
}

// getDerivedKey returns the cached derived key, deriving it once from env var
func getDerivedKey() ([]byte, error) {
	derivedKeyOnce.Do(func() {
		envKey := os.Getenv("SECRETS_ENCRYPTION_KEY")
		if envKey == "" {
			derivedKeyErr = ErrNoEncryptionKey
			return
		}

		// Derive a strong key using PBKDF2
		// Using fixed salt ensures same key is derived across restarts
		derivedKey = pbkdf2.Key([]byte(envKey), fixedSalt, pbkdf2Iterations, keyLength, sha256.New)

		// Also derive previous key if set (for rotation)
		if prevKey := os.Getenv("SECRETS_ENCRYPTION_KEY_PREV"); prevKey != "" {
			derivedKeyPrev = pbkdf2.Key([]byte(prevKey), fixedSalt, pbkdf2Iterations, keyLength, sha256.New)
		}
	})

	return derivedKey, derivedKeyErr
}

// GetKeyFingerprint returns a fingerprint of the current encryption key
// Used to detect key changes between deployments
func GetKeyFingerprint() (string, error) {
	key, err := getDerivedKey()
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(key)
	return base64.StdEncoding.EncodeToString(hash[:16]), nil // First 16 bytes is enough
}

// GetPrevKeyFingerprint returns a fingerprint of the previous encryption key
// Returns empty string if no previous key is configured
func GetPrevKeyFingerprint() string {
	getDerivedKey() // Ensure keys are derived
	if derivedKeyPrev == nil {
		return ""
	}
	hash := sha256.Sum256(derivedKeyPrev)
	return base64.StdEncoding.EncodeToString(hash[:16])
}

// HasPreviousKey returns true if a previous key is configured for rotation
func HasPreviousKey() bool {
	getDerivedKey() // Ensure keys are derived
	return derivedKeyPrev != nil
}

// ReEncrypt re-encrypts a v2 value with the current key
// Only the DEK is re-encrypted - data stays untouched (fast!)
// Returns the original value if it's not encrypted
func ReEncrypt(ciphertext string) (string, error) {
	if ciphertext == "" || !IsV2Encrypted(ciphertext) {
		return ciphertext, nil
	}

	getDerivedKey() // Ensure keys are derived
	if derivedKeyPrev == nil {
		return "", errors.New("SECRETS_ENCRYPTION_KEY_PREV not configured for re-encryption")
	}

	prevEnc := &SecretsEncryption{key: derivedKeyPrev}
	currentEnc := &SecretsEncryption{key: derivedKey}

	return reEncryptV2DEK(ciphertext, prevEnc, currentEnc)
}

// reEncryptV2DEK re-encrypts only the DEK of a v2 encrypted value
// The encrypted data stays exactly the same
func reEncryptV2DEK(ciphertext string, prevEnc, currentEnc *SecretsEncryption) (string, error) {
	// Parse format: enc:v2:<encrypted_dek>:<encrypted_data>
	content := strings.TrimPrefix(ciphertext, EncryptionPrefixV2)
	parts := strings.SplitN(content, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("%w: invalid v2 format", ErrInvalidCiphertext)
	}

	// Decode encrypted DEK
	encryptedDEK, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("%w: DEK base64 decode failed: %v", ErrInvalidCiphertext, err)
	}

	// Decrypt DEK with old KEK
	dek, err := prevEnc.decryptRaw(encryptedDEK)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt DEK with previous key: %w", err)
	}

	// Re-encrypt DEK with new KEK
	newEncryptedDEK, err := currentEnc.encryptRaw(dek)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt DEK with new key: %w", err)
	}

	// Return with new DEK but same encrypted data
	return EncryptionPrefixV2 +
		base64.StdEncoding.EncodeToString(newEncryptedDEK) + ":" +
		parts[1], nil // parts[1] is the original encrypted data, unchanged
}

// IsEncryptionEnabled returns true if secrets encryption is configured
func IsEncryptionEnabled() bool {
	_, err := getDerivedKey()
	return err == nil
}

// Encrypt encrypts a plaintext secret value using envelope encryption (v2)
// Returns the original value if encryption is disabled
func (e *SecretsEncryption) Encrypt(plaintext string) (string, error) {
	if e == nil || len(e.key) == 0 {
		return plaintext, nil // Encryption disabled
	}

	if plaintext == "" {
		return "", nil
	}

	// Already encrypted?
	if strings.HasPrefix(plaintext, EncryptionPrefixV1) || strings.HasPrefix(plaintext, EncryptionPrefixV2) {
		return plaintext, nil
	}

	// Generate random DEK (Data Encryption Key)
	dek := make([]byte, dekLength)
	if _, err := rand.Read(dek); err != nil {
		return "", fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Encrypt DEK with KEK
	encryptedDEK, err := e.encryptRaw(dek)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	// Encrypt data with DEK
	encryptedData, err := encryptWithKey(dek, []byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Format: enc:v2:<encrypted_dek>:<encrypted_data>
	return EncryptionPrefixV2 +
		base64.StdEncoding.EncodeToString(encryptedDEK) + ":" +
		base64.StdEncoding.EncodeToString(encryptedData), nil
}

// encryptRaw encrypts raw bytes with the KEK (no base64, no prefix)
func (e *SecretsEncryption) encryptRaw(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptRaw decrypts raw bytes with the KEK
func (e *SecretsEncryption) decryptRaw(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceLength {
		return nil, ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := ciphertext[:nonceLength]
	ciphertextBytes := ciphertext[nonceLength:]

	return gcm.Open(nil, nonce, ciphertextBytes, nil)
}

// encryptWithKey encrypts data with a given key (used for DEK encryption)
func encryptWithKey(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptWithKey decrypts data with a given key (used for DEK decryption)
func decryptWithKey(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceLength {
		return nil, ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := ciphertext[:nonceLength]
	ciphertextBytes := ciphertext[nonceLength:]

	return gcm.Open(nil, nonce, ciphertextBytes, nil)
}

// Decrypt decrypts an encrypted secret value (supports both v1 and v2)
// Returns the original value if it's not encrypted
func (e *SecretsEncryption) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	// Handle v2 (envelope encryption)
	if strings.HasPrefix(ciphertext, EncryptionPrefixV2) {
		return e.decryptV2(ciphertext)
	}

	// Handle v1 (direct encryption)
	if strings.HasPrefix(ciphertext, EncryptionPrefixV1) {
		return e.decryptV1(ciphertext)
	}

	// Not encrypted - return as-is (plain text)
	return ciphertext, nil
}

// decryptV1 decrypts a v1 encrypted value (direct encryption with KEK)
func (e *SecretsEncryption) decryptV1(ciphertext string) (string, error) {
	if e == nil || len(e.key) == 0 {
		return "", ErrNoEncryptionKey
	}

	encoded := strings.TrimPrefix(ciphertext, EncryptionPrefixV1)
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("%w: base64 decode failed: %v", ErrInvalidCiphertext, err)
	}

	plaintext, err := e.decryptRaw(data)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return string(plaintext), nil
}

// decryptV2 decrypts a v2 encrypted value (envelope encryption with DEK/KEK)
func (e *SecretsEncryption) decryptV2(ciphertext string) (string, error) {
	if e == nil || len(e.key) == 0 {
		return "", ErrNoEncryptionKey
	}

	// Parse format: enc:v2:<encrypted_dek>:<encrypted_data>
	content := strings.TrimPrefix(ciphertext, EncryptionPrefixV2)
	parts := strings.SplitN(content, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("%w: invalid v2 format", ErrInvalidCiphertext)
	}

	// Decode encrypted DEK
	encryptedDEK, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("%w: DEK base64 decode failed: %v", ErrInvalidCiphertext, err)
	}

	// Decode encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("%w: data base64 decode failed: %v", ErrInvalidCiphertext, err)
	}

	// Decrypt DEK with KEK
	dek, err := e.decryptRaw(encryptedDEK)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	// Decrypt data with DEK
	plaintext, err := decryptWithKey(dek, encryptedData)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return string(plaintext), nil
}

// IsEncrypted returns true if the value appears to be encrypted (v1 or v2)
func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, EncryptionPrefixV1) || strings.HasPrefix(value, EncryptionPrefixV2)
}

// IsV1Encrypted returns true if the value is encrypted with v1 (direct encryption)
func IsV1Encrypted(value string) bool {
	return strings.HasPrefix(value, EncryptionPrefixV1)
}

// IsV2Encrypted returns true if the value is encrypted with v2 (envelope encryption)
func IsV2Encrypted(value string) bool {
	return strings.HasPrefix(value, EncryptionPrefixV2)
}

// EncryptValue is a convenience function for one-off encryption
func EncryptValue(plaintext string) (string, error) {
	enc, err := NewSecretsEncryption()
	if err != nil {
		return "", err
	}
	if enc == nil {
		return plaintext, nil // Encryption disabled
	}
	return enc.Encrypt(plaintext)
}

// DecryptValue is a convenience function for one-off decryption
func DecryptValue(ciphertext string) (string, error) {
	enc, err := NewSecretsEncryption()
	if err != nil {
		return "", err
	}
	if enc == nil {
		// If not encrypted, return as-is
		if !IsEncrypted(ciphertext) {
			return ciphertext, nil
		}
		return "", ErrNoEncryptionKey
	}
	return enc.Decrypt(ciphertext)
}
