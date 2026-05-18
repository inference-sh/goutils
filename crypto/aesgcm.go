package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"

	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"runtime"

	"golang.org/x/crypto/argon2"
)

// KeySize is the required size of encryption keys in bytes (32 bytes for AES-256)
const KeySize = 32

// ErrInvalidKeySize is returned when an encryption key of incorrect size is provided
var ErrInvalidKeySize = fmt.Errorf("invalid key size: must be %d bytes", KeySize)

// Reader wraps an io.Reader with encryption
type Reader struct {
	reader    io.Reader
	aead      cipher.AEAD
	nonce     []byte
	buf       []byte
	encrypted []byte
	offset    int
	eof       bool
	counter   uint64 // Counter for generating unique nonces
}

// DecryptReader wraps an io.Reader with decryption
type DecryptReader struct {
	reader    io.Reader
	aead      cipher.AEAD
	nonce     []byte
	buf       []byte
	decrypted []byte
	offset    int
	eof       bool
	counter   uint64 // Counter for generating unique nonces
}

// deriveKey derives an encryption key from a passphrase using Argon2id
func deriveKey(passphrase string, salt []byte) []byte {
	// Use Argon2id with secure parameters
	return argon2.IDKey(
		[]byte(passphrase),
		salt,
		1,       // Time cost
		64*1024, // Memory cost (64MB)
		4,       // Parallelism
		KeySize, // Key length (for AES-256)
	)
}

// validateKey checks if the provided key is valid for encryption/decryption
func validateKey(key []byte) error {
	if len(key) != KeySize {
		return ErrInvalidKeySize
	}
	return nil
}

// generateNonce generates a unique nonce using a cryptographically secure combination
// of the base nonce and counter. For GCM, we use 12-byte nonces as recommended.
func generateNonce(baseNonce []byte, counter uint64) []byte {
	if len(baseNonce) != 12 { // GCM requires 12-byte nonces for best security
		panic("base nonce must be 12 bytes")
	}

	// Create result nonce
	nonce := make([]byte, 12)

	// Convert counter to bytes (8 bytes)
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	// Mix counter with base nonce using a more complex pattern
	// First 4 bytes: XOR of base nonce[0:4] with counter bytes rotated
	for i := 0; i < 4; i++ {
		nonce[i] = baseNonce[i] ^ counterBytes[(i+4)%8]
	}

	// Middle 4 bytes: XOR of base nonce[4:8] with counter directly
	for i := 0; i < 4; i++ {
		nonce[i+4] = baseNonce[i+4] ^ counterBytes[i]
	}

	// Last 4 bytes: XOR of base nonce[8:12] with counter bytes and rotation
	for i := 0; i < 4; i++ {
		nonce[i+8] = baseNonce[i+8] ^ counterBytes[(i+2)%8]
	}

	return nonce
}

// NewEncryptReader creates a new encrypting reader using a passphrase
func NewEncryptReader(r io.Reader, passphrase string) (*Reader, error) {
	// Generate a random salt for key derivation
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	key := deriveKey(passphrase, salt)
	return NewEncryptReaderWithKey(r, key, salt)
}

// NewEncryptReaderWithKey creates a new encrypting reader using a raw 32-byte key.
// The key must be exactly 32 bytes (256 bits) for AES-256-GCM.
// If using a passphrase, use NewEncryptReader instead.
func NewEncryptReaderWithKey(r io.Reader, key []byte, salt []byte) (*Reader, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Generate random base nonce (12 bytes for GCM)
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Write header: salt length + salt + base nonce
	header := make([]byte, 8+len(salt)+len(nonce))
	binary.LittleEndian.PutUint64(header[0:8], uint64(len(salt)))
	copy(header[8:], salt)
	copy(header[8+len(salt):], nonce)

	return &Reader{
		reader:    r,
		aead:      aead,
		nonce:     nonce,
		buf:       make([]byte, 32*1024), // 32KB chunks
		encrypted: header,
		offset:    0,
		counter:   0,
	}, nil
}

// Read implements io.Reader
func (er *Reader) Read(p []byte) (int, error) {
	// First, output the header if not done yet
	if er.offset < len(er.encrypted) {
		n := copy(p, er.encrypted[er.offset:])
		er.offset += n
		return n, nil
	}

	// If we've reached EOF and processed all encrypted data
	if er.eof && er.offset >= len(er.encrypted) {
		return 0, io.EOF
	}

	// Read from source if we need more data
	if !er.eof && er.offset >= len(er.encrypted) {
		n, err := er.reader.Read(er.buf)
		if err != nil {
			if err != io.EOF {
				return 0, err
			}
			er.eof = true
		}

		if n > 0 {
			// Generate unique nonce for this chunk
			chunkNonce := generateNonce(er.nonce, er.counter)
			er.counter++

			// Encrypt the chunk with the unique nonce, allocating space for the tag
			tagSize := er.aead.Overhead()
			er.encrypted = make([]byte, 0, n+tagSize)
			er.encrypted = er.aead.Seal(er.encrypted, chunkNonce, er.buf[:n], nil)
			er.offset = 0
		}
	}

	// Copy encrypted data to output buffer
	n := copy(p, er.encrypted[er.offset:])
	er.offset += n
	return n, nil
}

// CalculateOverhead calculates the total overhead added by encryption
func CalculateOverhead(fileSize int64) int64 {
	// Header size (salt length (8) + salt (16) + nonce (12)) and per-chunk overhead
	return 36 + (fileSize/32768+1)*16 // 16 bytes overhead per chunk
}

// NewDecryptReader creates a new decrypting reader using a passphrase
func NewDecryptReader(r io.Reader, passphrase string) (*DecryptReader, error) {
	// Read header: salt length (8 bytes)
	var saltLen uint64
	if err := binary.Read(r, binary.LittleEndian, &saltLen); err != nil {
		return nil, fmt.Errorf("failed to read salt length: %v", err)
	}

	// Read salt
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, fmt.Errorf("failed to read salt: %v", err)
	}

	key := deriveKey(passphrase, salt)
	return NewDecryptReaderWithKey(r, key)
}

// NewDecryptReaderWithKey creates a new decrypting reader using a raw 32-byte key.
// The key must be exactly 32 bytes (256 bits) for AES-256-GCM.
// If using a passphrase, use NewDecryptReader instead.
func NewDecryptReaderWithKey(r io.Reader, key []byte) (*DecryptReader, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Read base nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %v", err)
	}

	// Buffer size needs to be large enough to hold encrypted data + GCM tag
	bufSize := 32*1024 + aead.Overhead() // 32KB + GCM tag size

	return &DecryptReader{
		reader:  r,
		aead:    aead,
		nonce:   nonce,
		buf:     make([]byte, bufSize),
		counter: 0,
	}, nil
}

// Read implements io.Reader
func (dr *DecryptReader) Read(p []byte) (int, error) {
	// If we have decrypted data available, return it
	if dr.offset < len(dr.decrypted) {
		n := copy(p, dr.decrypted[dr.offset:])
		dr.offset += n
		return n, nil
	}

	// If we've reached EOF and processed all decrypted data
	if dr.eof && dr.offset >= len(dr.decrypted) {
		return 0, io.EOF
	}

	// Read next chunk - ensure we read the full chunk unless we hit EOF
	n, err := io.ReadFull(dr.reader, dr.buf)
	if err != nil {
		if err == io.EOF {
			dr.eof = true
			return 0, io.EOF
		}
		if err == io.ErrUnexpectedEOF {
			// This is fine - we got a partial chunk at the end
			dr.eof = true
		} else {
			return 0, err
		}
	}

	if n > 0 {
		// Each encrypted chunk includes a 16-byte GCM tag at the end
		tagSize := dr.aead.Overhead()
		if n < tagSize {
			return 0, fmt.Errorf("encrypted chunk too small: got %d bytes, need at least %d bytes", n, tagSize)
		}

		// Generate unique nonce for this chunk
		chunkNonce := generateNonce(dr.nonce, dr.counter)
		dr.counter++

		// Decrypt the chunk
		var decErr error
		dr.decrypted, decErr = dr.aead.Open(nil, chunkNonce, dr.buf[:n], nil)
		if decErr != nil {
			return 0, fmt.Errorf("failed to decrypt (chunk %d, size %d): %v", dr.counter-1, n, decErr)
		}
		dr.offset = 0
	}

	// Copy decrypted data to output buffer
	n = copy(p, dr.decrypted[dr.offset:])
	dr.offset += n
	return n, nil
}

// EncryptBytes encrypts a byte slice using the given passphrase
func EncryptBytes(data []byte, passphrase string) ([]byte, error) {
	reader := bytes.NewReader(data)
	encReader, err := NewEncryptReader(reader, passphrase)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(encReader)
}

// EncryptBytesWithKey encrypts a byte slice using the given key
func EncryptBytesWithKey(data []byte, key []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	encReader, err := NewEncryptReaderWithKey(reader, key, nil)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(encReader)
}

// DecryptBytes decrypts a byte slice that was encrypted with EncryptBytes
func DecryptBytes(encrypted []byte, passphrase string) ([]byte, error) {
	reader := bytes.NewReader(encrypted)
	decReader, err := NewDecryptReader(reader, passphrase)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(decReader)
}

func DecryptBytesWithKey(encrypted []byte, key []byte) ([]byte, error) {
	reader := bytes.NewReader(encrypted)
	decReader, err := NewDecryptReaderWithKey(reader, key)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(decReader)
}

// secureWipe overwrites the data with zeros to ensure it's not left in memory
func secureWipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
	runtime.KeepAlive(data) // Prevent compiler optimization from skipping the wipe
}

// KeyPair holds the generated key pair with secure cleanup
type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// Cleanup securely wipes the key pair from memory
func (kp *KeyPair) Cleanup() {
	if kp.PrivateKey != nil {
		secureWipe(kp.PrivateKey)
		kp.PrivateKey = nil
	}
	if kp.PublicKey != nil {
		secureWipe(kp.PublicKey)
		kp.PublicKey = nil
	}
}

// GenerateKeyPair generates a new ECDSA key pair with secure memory handling
func GenerateKeyPair() (*KeyPair, error) {
	keyPair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Encode private key to PEM
	privKeyBytes, err := x509.MarshalECPrivateKey(keyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	secureWipe(privKeyBytes) // Clean up the temporary buffer

	// Encode public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey)
	if err != nil {
		secureWipe(privKeyPEM)
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	secureWipe(pubKeyBytes) // Clean up the temporary buffer

	return &KeyPair{
		PublicKey:  pubKeyPEM,
		PrivateKey: privKeyPEM,
	}, nil
}
