package crypto

import (
	"bytes"
	"testing"
)

func TestECIESRoundtrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte(`{"HF_TOKEN":"hf_abc123","API_KEY":"sk-secret"}`)

	encrypted, err := ECIESEncrypt(string(kp.PublicKey), plaintext)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := ECIESDecrypt(string(kp.PrivateKey), encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestECIESWrongKey(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	encrypted, err := ECIESEncrypt(string(kp1.PublicKey), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = ECIESDecrypt(string(kp2.PrivateKey), encrypted)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestECIESTooShort(t *testing.T) {
	kp, _ := GenerateKeyPair()
	_, err := ECIESDecrypt(string(kp.PrivateKey), []byte("short"))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestECIESEmptyPlaintext(t *testing.T) {
	kp, _ := GenerateKeyPair()

	encrypted, err := ECIESEncrypt(string(kp.PublicKey), []byte{})
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := ECIESDecrypt(string(kp.PrivateKey), encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(decrypted))
	}
}
