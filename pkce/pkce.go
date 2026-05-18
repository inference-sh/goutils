package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// PKCEPair is an RFC 7636 PKCE verifier/challenge pair using the S256 method.
//
// Verifier: 64 bytes of random entropy, base64url-encoded (86 chars, well
// within the 43–128 range the spec requires).
// Challenge: base64url(sha256(verifier)).
type PKCEPair struct {
	Verifier  string
	Challenge string // S256 of Verifier
}

// GeneratePKCE returns a fresh verifier/challenge pair (S256 method).
// Panics only if the system random source fails, which is catastrophic
// enough that callers should not try to recover.
func GeneratePKCE() PKCEPair {
	var seed [64]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic("pkce: crypto/rand.Read failed: " + err.Error())
	}
	verifier := base64.RawURLEncoding.EncodeToString(seed[:])
	sum := sha256.Sum256([]byte(verifier))
	return PKCEPair{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
	}
}

// PKCEChallengeFromVerifier recomputes the S256 challenge for an existing
// verifier. Used on the token-exchange side when validating.
func PKCEChallengeFromVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
