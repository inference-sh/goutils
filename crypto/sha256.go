package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

// Sha256 returns the hex-encoded SHA256 hash of the given data.
func Sha256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
