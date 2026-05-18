package crypto

import "sync"

// ResetForTesting resets the cached encryption keys so they will be
// re-derived from environment variables on next use. Only for tests.
func ResetForTesting() {
	derivedKey = nil
	derivedKeyPrev = nil
	derivedKeyOnce = sync.Once{}
	derivedKeyErr = nil
}
