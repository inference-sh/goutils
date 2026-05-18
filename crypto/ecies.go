package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ECIESEncrypt encrypts plaintext using the recipient's PEM-encoded ECDSA public key.
// Returns: ephemeralPub (65 bytes) || nonce (12 bytes) || ciphertext+tag
func ECIESEncrypt(pubKeyPEM string, plaintext []byte) ([]byte, error) {
	pub, err := parseECDSAPublicKey(pubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("ecies: %w", err)
	}

	recipientPub, err := convertECDSAToECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ecies: convert public key: %w", err)
	}

	// Generate ephemeral keypair
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecies: generate ephemeral key: %w", err)
	}

	// ECDH → shared secret → AES key
	aesKey, err := deriveECIESKey(ephemeral, recipientPub)
	if err != nil {
		return nil, err
	}

	// AES-256-GCM encrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("ecies: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ecies: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("ecies: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Wire format: ephemeralPub (65) || nonce (12) || ciphertext+tag
	ephPub := ephemeral.PublicKey().Bytes() // 65 bytes uncompressed
	out := make([]byte, 0, len(ephPub)+len(nonce)+len(ciphertext))
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// ECIESDecrypt decrypts ciphertext using the recipient's PEM-encoded ECDSA private key.
// Expects the wire format produced by ECIESEncrypt.
func ECIESDecrypt(privKeyPEM string, data []byte) ([]byte, error) {
	priv, err := parseECDSAPrivateKey(privKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("ecies: %w", err)
	}

	ecdhPriv, err := priv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("ecies: convert private key: %w", err)
	}

	// Parse wire format
	const ephPubLen = 65 // uncompressed P-256 point
	const nonceLen = 12  // GCM nonce
	if len(data) < ephPubLen+nonceLen+1 {
		return nil, fmt.Errorf("ecies: ciphertext too short")
	}

	ephPub, err := ecdh.P256().NewPublicKey(data[:ephPubLen])
	if err != nil {
		return nil, fmt.Errorf("ecies: parse ephemeral key: %w", err)
	}
	nonce := data[ephPubLen : ephPubLen+nonceLen]
	ciphertext := data[ephPubLen+nonceLen:]

	// ECDH → same shared secret → same AES key
	aesKey, err := deriveECIESKey(ecdhPriv, ephPub)
	if err != nil {
		return nil, err
	}

	// AES-256-GCM decrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("ecies: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ecies: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("ecies: decrypt failed (wrong key or tampered data)")
	}
	return plaintext, nil
}

// deriveECIESKey performs ECDH and derives a 32-byte AES key via SHA-256.
func deriveECIESKey(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ecies: ECDH failed: %w", err)
	}
	key := sha256.Sum256(shared)
	return key[:], nil
}

// parseECDSAPublicKey parses a PEM-encoded ECDSA public key.
func parseECDSAPublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}
	return ecPub, nil
}

// parseECDSAPrivateKey parses a PEM-encoded ECDSA private key.
func parseECDSAPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return priv, nil
}
