package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

var (
	// ErrInvalidUmbralKeySize is returned when a key has an invalid size
	ErrInvalidUmbralKeySize = errors.New("invalid umbral key size")
	// ErrInvalidUmbralCapsule is returned when a capsule is invalid
	ErrInvalidUmbralCapsule = errors.New("invalid umbral capsule")
	// ErrInvalidUmbralReEncryptionKey is returned when a re-encryption key is invalid
	ErrInvalidUmbralReEncryptionKey = errors.New("invalid umbral re-encryption key")
)

// UmbralKeyPair represents an Umbral key pair
type UmbralKeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// UmbralCapsule represents an Umbral capsule containing the encrypted key
type UmbralCapsule struct {
	E *big.Int // Point on the curve
	V *big.Int // Point on the curve
	S *big.Int // Scalar
}

// UmbralReEncryptionKey represents a key that allows re-encryption
type UmbralReEncryptionKey struct {
	Rk         *big.Int // as before
	DelegateeX *big.Int // as before
	X          *big.Int // NEW:  g^x  (only the X‑coordinate is enough for the PoC)
}

// GenerateUmbralKeyPair generates a new Umbral key pair
func GenerateUmbralKeyPair() (*UmbralKeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return &UmbralKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// deriveUmbralKey derives a symmetric key from a shared secret for Umbral encryption
func deriveUmbralKey(sharedSecret *big.Int) []byte {
	// Convert shared secret to bytes
	secretBytes := sharedSecret.Bytes()

	// Use SHA-256 to derive encryption key
	key := sha256.Sum256(secretBytes)
	return key[:]
}

// convertECDSAToECDH converts an ECDSA public key to ECDH format
func convertECDSAToECDH(pub *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	curve := ecdh.P256()

	// Convert ECDSA public key to ECDH format
	pubBytes := make([]byte, 1+32+32) // 1 byte prefix + 32 bytes X + 32 bytes Y
	pubBytes[0] = 0x04                // uncompressed point format

	// Ensure X and Y are properly padded to 32 bytes
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	pub.X.FillBytes(xBytes)
	pub.Y.FillBytes(yBytes)

	copy(pubBytes[1:33], xBytes)
	copy(pubBytes[33:], yBytes)

	return curve.NewPublicKey(pubBytes)
}

// calculateYCoordinate calculates the Y coordinate for a given X coordinate on the P-256 curve
func calculateYCoordinate(x *big.Int) (*big.Int, error) {
	// y^2 = x^3 + ax + b (mod p)
	// For P-256: a = -3 (mod p), b as given by the curve parameters.

	params := elliptic.P256().Params()
	p := params.P
	b := params.B

	// Compute x^3 mod p
	x2 := new(big.Int).Mul(x, x) // x^2
	x2.Mod(x2, p)
	x3 := new(big.Int).Mul(x2, x) // x^3
	x3.Mod(x3, p)

	// Compute a*x where a = -3 mod p (i.e. p-3)
	a := new(big.Int).Sub(p, big.NewInt(3)) // a = p - 3 which is equivalent to -3 mod p
	ax := new(big.Int).Mul(a, x)
	ax.Mod(ax, p)

	// y2 = x^3 + a*x + b (mod p)
	y2 := new(big.Int).Add(x3, ax)
	y2.Add(y2, b)
	y2.Mod(y2, p)

	// Calculate square root (ModSqrt returns nil if no sqrt exists)
	y := new(big.Int).ModSqrt(y2, p)
	if y == nil {
		return nil, fmt.Errorf("no square root exists")
	}

	// Either y or p-y will be a valid coordinate. Choose the one that forms a valid point.
	if !elliptic.P256().IsOnCurve(x, y) {
		y.Sub(p, y)
		if !elliptic.P256().IsOnCurve(x, y) {
			return nil, fmt.Errorf("point not on curve")
		}
	}

	return y, nil
}

// UmbralEncrypt encrypts a message using the recipient's public key
func UmbralEncrypt(publicKey *ecdsa.PublicKey, message []byte) (*UmbralCapsule, []byte, error) {
	curve := ecdh.P256()
	order := elliptic.P256().Params().N

	// Generate random scalar r
	r, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random scalar: %w", err)
	}

	// Create private key from random scalar
	priv, err := curve.NewPrivateKey(r.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create private key: %w", err)
	}

	// Get public key (E = r * G)
	pub := priv.PublicKey()
	pubBytes := pub.Bytes()
	E_x := new(big.Int).SetBytes(pubBytes[1:33])

	// Convert recipient's public key to ECDH format
	recipientPub, err := convertECDSAToECDH(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert recipient public key: %w", err)
	}

	// Calculate shared secret (V = r * recipient_public_key)
	sharedSecret, err := priv.ECDH(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate shared secret: %w", err)
	}

	// Calculate V point using ECDH
	V_shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate V point: %w", err)
	}

	V_x := new(big.Int).SetBytes(V_shared[:32])

	// Calculate S = E_x + H(E,V) * recipient_public_key.X
	h := sha256.New()
	h.Write(E_x.Bytes())
	h.Write(V_x.Bytes())
	hash := new(big.Int).SetBytes(h.Sum(nil))
	hash.Mod(hash, order)

	S := new(big.Int).Mul(hash, publicKey.X)
	S.Add(S, E_x)
	S.Mod(S, order)

	// Create capsule
	capsule := &UmbralCapsule{
		E: E_x,
		V: V_x,
		S: S,
	}

	// Derive symmetric key from shared secret
	key := deriveUmbralKey(new(big.Int).SetBytes(sharedSecret[:32]))

	// XOR message with key
	encrypted := make([]byte, len(message))
	for i := range message {
		encrypted[i] = message[i] ^ key[i%len(key)]
	}

	return capsule, encrypted, nil
}

// UmbralDecrypt decrypts a message using the recipient's private key
func UmbralDecrypt(privateKey *ecdsa.PrivateKey, capsule *UmbralCapsule, encrypted []byte) ([]byte, error) {
	if capsule == nil {
		return nil, ErrInvalidUmbralCapsule
	}

	curve := ecdh.P256()

	// Create private key from recipient's private key
	priv, err := curve.NewPrivateKey(privateKey.D.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to create private key: %w", err)
	}

	// Reconstruct the missing Y coordinate for E so we can obtain a valid point
	E_y, err := calculateYCoordinate(capsule.E)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct E.y coordinate: %w", err)
	}

	// Convert capsule E (with both coordinates) to ECDH public key
	E_pub, err := convertECDSAToECDH(&ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     capsule.E,
		Y:     E_y,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to convert capsule E: %w", err)
	}

	// Calculate shared secret
	sharedSecret, err := priv.ECDH(E_pub)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate shared secret: %w", err)
	}

	// Verify capsule
	h := sha256.New()
	h.Write(capsule.E.Bytes())
	h.Write(capsule.V.Bytes())
	hash := new(big.Int).SetBytes(h.Sum(nil))
	hash.Mod(hash, elliptic.P256().Params().N)

	// Calculate S' = E + H(E,V) * recipient_public_key
	S_prime := new(big.Int).Mul(hash, privateKey.PublicKey.X)
	S_prime.Add(S_prime, capsule.E)
	S_prime.Mod(S_prime, elliptic.P256().Params().N)

	if S_prime.Cmp(capsule.S) != 0 {
		return nil, fmt.Errorf("capsule verification failed")
	}

	// Derive decryption key
	key := deriveUmbralKey(new(big.Int).SetBytes(sharedSecret[:32]))

	// XOR encrypted message with key
	decrypted := make([]byte, len(encrypted))
	for i := range encrypted {
		decrypted[i] = encrypted[i] ^ key[i%len(key)]
	}

	return decrypted, nil
}

// --------------------------------------------------------------------
// 1. GenerateUmbralReEncryptionKey   (Bob → proxy)
// --------------------------------------------------------------------
func GenerateUmbralReEncryptionKey(
	delegatorPriv *ecdsa.PrivateKey,
	delegateePub *ecdsa.PublicKey) (*UmbralReEncryptionKey, error) {

	n := elliptic.P256().Params().N // curve order

	// 1)  x ∈ [1,n-1]
	x, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, fmt.Errorf("rand failure: %w", err)
	}

	// 2) build an *ecdh.PrivateKey from x  →  X = gˣ
	ecdhCurve := ecdh.P256()
	xPriv, err := ecdhCurve.NewPrivateKey(x.Bytes())
	if err != nil {
		return nil, err
	}

	XpubBytes := xPriv.PublicKey().Bytes()       // 65‑byte uncompressed
	Xx := new(big.Int).SetBytes(XpubBytes[1:33]) // keep X‑coord only

	// 3)  Z = PK_Cˣ  via ECDH with Charlie’s public key
	charlieECDH, err := convertECDSAToECDH(delegateePub)
	if err != nil {
		return nil, err
	}

	shared, err := xPriv.ECDH(charlieECDH) // 32‑byte shared secret
	if err != nil {
		return nil, err
	}
	Zx := new(big.Int).SetBytes(shared[:32]) // use X‑coord for hash

	// 4)  d = H( Xx ‖ PK_C.x ‖ Zx )
	h := sha256.New()
	h.Write(Xx.Bytes())
	h.Write(delegateePub.X.Bytes())
	h.Write(Zx.Bytes())
	d := new(big.Int).SetBytes(h.Sum(nil))
	d.Mod(d, n)
	if d.Sign() == 0 {
		return nil, errors.New("hash‑to‑field returned 0")
	}

	// 5)  rk = d⁻¹ · d_Bob     (mod n)
	dInv := new(big.Int).ModInverse(d, n)
	rk := new(big.Int).Mul(dInv, delegatorPriv.D)
	rk.Mod(rk, n)

	return &UmbralReEncryptionKey{
		Rk:         rk,
		DelegateeX: delegateePub.X,
		X:          Xx, // send to proxy → Charlie
	}, nil
}

// pad32 left-pads a byte slice to 32 bytes.
func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// --------------------------------------------------------------------
// 2. UmbralReEncrypt   (proxy)
// --------------------------------------------------------------------
func UmbralReEncrypt(rk *UmbralReEncryptionKey,
	cap *UmbralCapsule) (*UmbralCapsule, *big.Int) {

	if rk == nil || cap == nil {
		return nil, nil
	}

	ecdhCurve := ecdh.P256()
	n := elliptic.P256().Params().N

	// helper: build an ECDH PublicKey from an X‑coord
	makePub := func(x *big.Int) (*ecdh.PublicKey, error) {
		y, err := calculateYCoordinate(x)
		if err != nil {
			return nil, err
		}
		return ecdhCurve.NewPublicKey(append(
			[]byte{0x04},
			append(pad32(x.Bytes()), pad32(y.Bytes())...)...))
	}

	rkPriv, _ := ecdhCurve.NewPrivateKey(rk.Rk.Bytes())

	// transform E
	Epub, _ := makePub(cap.E)
	newEshared, _ := rkPriv.ECDH(Epub)
	newEx := new(big.Int).SetBytes(newEshared[:32])

	// transform V
	Vpub, _ := makePub(cap.V)
	newVshared, _ := rkPriv.ECDH(Vpub)
	newVx := new(big.Int).SetBytes(newVshared[:32])

	// new S
	h := sha256.New()
	h.Write(newEx.Bytes())
	h.Write(newVx.Bytes())
	hash := new(big.Int).SetBytes(h.Sum(nil))
	hash.Mod(hash, n)

	newS := new(big.Int).Mul(hash, rk.DelegateeX)
	newS.Add(newS, newEx)
	newS.Mod(newS, n)

	return &UmbralCapsule{E: newEx, V: newVx, S: newS}, rk.X
}

// UmbralDecryptReEncrypted lets Charlie recover the plaintext
// from a proxy‑re‑encrypted capsule (caps′, X).
func UmbralDecryptReEncrypted(
	delegateePriv *ecdsa.PrivateKey, // Charlie
	origPubKey *ecdsa.PublicKey, // Bob (unused but kept for API symmetry)
	caps *UmbralCapsule, // E′,V′,S′
	pointX *big.Int, // X = gˣ (only its X‑coord)
	cipherText []byte) ([]byte, error) {

	if caps == nil {
		return nil, ErrInvalidUmbralCapsule
	}

	// ── 1. Recompute d  ────────────────────────────────────────────────
	yX, err := calculateYCoordinate(pointX)
	if err != nil {
		return nil, fmt.Errorf("reconstruct X.y failed: %w", err)
	}

	ecdhCurve := ecdh.P256()
	// X as an ECDH PublicKey
	Xpub, _ := ecdhCurve.NewPublicKey(
		append([]byte{0x04},
			append(pad32(pointX.Bytes()), pad32(yX.Bytes())...)...))

	cPriv, _ := ecdhCurve.NewPrivateKey(delegateePriv.D.Bytes())
	Zshared, _ := cPriv.ECDH(Xpub) // Z = d_C · X
	Zx := new(big.Int).SetBytes(Zshared[:32])

	h := sha256.New()
	h.Write(pointX.Bytes())
	h.Write(delegateePriv.PublicKey.X.Bytes())
	h.Write(Zx.Bytes())
	n := elliptic.P256().Params().N
	d := new(big.Int).SetBytes(h.Sum(nil))
	d.Mod(d, n)
	if d.Sign() == 0 {
		return nil, errors.New("hash‑to‑field is zero")
	}

	// ── 2. shared = d · E′  (NOT d·(E′+V′)) ───────────────────────────
	Ey, err := calculateYCoordinate(caps.E)
	if err != nil {
		return nil, err
	}
	sharedX, _ := elliptic.P256().ScalarMult(caps.E, Ey, d.Bytes())

	// ── 3. Derive key & decrypt  ───────────────────────────────────────
	key := deriveUmbralKey(sharedX)

	plain := make([]byte, len(cipherText))
	for i := range cipherText {
		plain[i] = cipherText[i] ^ key[i%len(key)]
	}
	return plain, nil
}
