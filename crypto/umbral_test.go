package crypto

import (
	"testing"
)

func TestUmbralEncryption(t *testing.T) {
	// Generate key pairs
	bob, err := GenerateUmbralKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Bob's key pair: %v", err)
	}

	// Test message
	message := []byte("Hello, Umbral!")

	// Encrypt message for Bob
	capsule, encrypted, err := UmbralEncrypt(bob.PublicKey, message)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	// Bob decrypts the message
	decrypted, err := UmbralDecrypt(bob.PrivateKey, capsule, encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt message: %v", err)
	}

	// Verify decrypted message matches original
	if string(decrypted) != string(message) {
		t.Errorf("Decrypted message does not match original: got %s, want %s", decrypted, message)
	}
}

func TestUmbralReEncryption(t *testing.T) {
	// Generate key pairs
	bob, err := GenerateUmbralKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Bob's key pair: %v", err)
	}

	charlie, err := GenerateUmbralKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Charlie's key pair: %v", err)
	}

	// Test message
	message := []byte("Hello, Umbral!")

	// Encrypt message for Bob
	capsule, encrypted, err := UmbralEncrypt(bob.PublicKey, message)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	// Bob generates a re-encryption key for Charlie
	reKey, err := GenerateUmbralReEncryptionKey(bob.PrivateKey, charlie.PublicKey)
	if err != nil {
		t.Fatalf("Failed to generate re-encryption key: %v", err)
	}

	// in TestUmbralReEncryption (or your own test)
	newCaps, X := UmbralReEncrypt(reKey, capsule)

	decrypted, err := UmbralDecryptReEncrypted(
		charlie.PrivateKey,
		bob.PublicKey,
		newCaps,
		X,
		encrypted)
	if err != nil {
		t.Fatalf("decap failed: %v", err)
	}

	// Verify decrypted message matches original
	if string(decrypted) != string(message) {
		t.Errorf("Decrypted message does not match original: got %s, want %s", decrypted, message)
	}
}

func TestUmbralInvalidCapsule(t *testing.T) {
	// Generate key pair
	keyPair, err := GenerateUmbralKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Try to decrypt with nil capsule
	_, err = UmbralDecrypt(keyPair.PrivateKey, nil, []byte("test"))
	if err != ErrInvalidUmbralCapsule {
		t.Errorf("Expected ErrInvalidUmbralCapsule, got %v", err)
	}
}

// func TestUmbralInvalidReEncryptionKey(t *testing.T) {
// 	// Create a test capsule
// 	capsule := &UmbralCapsule{
// 		E: big.NewInt(1),
// 		V: big.NewInt(1),
// 		S: big.NewInt(1),
// 	}

// 	// Try to re-encrypt with nil re-encryption key
// 	_, err := UmbralReEncrypt(nil, capsule)
// 	if err != ErrInvalidUmbralReEncryptionKey {
// 		t.Errorf("Expected ErrInvalidUmbralReEncryptionKey, got %v", err)
// 	}
// }
