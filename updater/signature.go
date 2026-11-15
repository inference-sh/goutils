package updater

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
)

// Release manifests are signed with ed25519. The signature is detached: it
// lives next to the manifest at <manifest URL>.sig and covers the manifest's
// exact bytes, so nothing has to agree on a canonical JSON form and readers
// that ignore signatures (install.sh, npm, Scoop, older binaries) see the
// manifest unchanged.
//
// The .sig file is text: one base64 (standard encoding) signature per line.
// It verifies when any line verifies under any trusted key, so a key is
// rotated by signing with both keys for a while.
//
// A signed manifest names its product ("product": "cli"), and that must be
// the first path segment of the URL it was fetched from
// (https://dist.inference.sh/cli/manifest.json). One key signs every
// product's manifests; without this an engine manifest served at the CLI's
// URL would verify, and the CLI would install the engine over itself.

// RequireSignature is the rollout switch.
//
// false (phase 1): a manifest with no .sig is accepted with a warning. One
// with a .sig is verified, and refused if the signature or product is wrong
// or the build picked from it has no sha256.
//
// true (phase 2): a manifest with no .sig, or a binary with no trusted keys,
// is refused too. Flip it once every manifest a binary can be pointed at is
// signed: the channel heads and every per-version manifest a pin or rollback
// can name.
var RequireSignature = false

// Warnf reports an accepted unsigned manifest. Binaries may redirect it.
var Warnf = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "warning: "+format+"\n", args...)
}

var (
	// ErrUnsigned is returned when RequireSignature is set and the manifest
	// has no signature or there are no trusted keys.
	ErrUnsigned = errors.New("release manifest is not signed")
	// ErrBadSignature is returned when no signature verifies under a
	// trusted key.
	ErrBadSignature = errors.New("release manifest signature does not verify")
)

var (
	keysMu      sync.RWMutex
	trustedKeys []ed25519.PublicKey
)

// SetTrustedKeys replaces the public keys release manifests are verified
// with. Each key is base64 (standard encoding) of a 32-byte ed25519 public
// key. A binary calls it once at start, before any update check, with the
// keys compiled into it. With no keys, phase 1 skips verification entirely.
func SetTrustedKeys(keys ...string) error {
	parsed := make([]ed25519.PublicKey, 0, len(keys))
	for _, k := range keys {
		pk, err := ParsePublicKey(k)
		if err != nil {
			return err
		}
		parsed = append(parsed, pk)
	}
	keysMu.Lock()
	trustedKeys = parsed
	keysMu.Unlock()
	return nil
}

// MustSetTrustedKeys is SetTrustedKeys for keys compiled into the binary,
// where a malformed key is a build mistake.
func MustSetTrustedKeys(keys ...string) {
	if err := SetTrustedKeys(keys...); err != nil {
		panic(err)
	}
}

func currentKeys() []ed25519.PublicKey {
	keysMu.RLock()
	defer keysMu.RUnlock()
	return trustedKeys
}

// ParsePublicKey decodes a base64 ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key %q: want base64 of %d bytes", s, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// ParsePrivateKey decodes a base64 ed25519 private key: the 32-byte seed
// (what manifestsig keygen prints) or the 64-byte expanded form.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("invalid ed25519 private key: not base64")
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		pk := ed25519.PrivateKey(b)
		// The expanded form carries its public half; reject one that does
		// not match its seed rather than sign with a key nobody trusts.
		if !bytes.Equal(ed25519.NewKeyFromSeed(pk.Seed()).Public().(ed25519.PublicKey), pk.Public().(ed25519.PublicKey)) {
			return nil, errors.New("invalid ed25519 private key: public half does not match")
		}
		return pk, nil
	}
	return nil, fmt.Errorf("invalid ed25519 private key: %d bytes, want %d or %d", len(b), ed25519.SeedSize, ed25519.PrivateKeySize)
}

// EncodePublicKey is the base64 form SetTrustedKeys takes.
func EncodePublicKey(pk ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pk)
}

// SignManifest returns one .sig file line: the base64 signature of manifest.
func SignManifest(priv ed25519.PrivateKey, manifest []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifest)) + "\n"
}

// SignatureURL is where the signature for manifestURL lives: the same URL
// with ".sig" appended to its path (a query string stays after it).
func SignatureURL(manifestURL string) (string, error) {
	u, err := url.Parse(manifestURL)
	if err != nil {
		return "", fmt.Errorf("parse manifest URL: %w", err)
	}
	u.Path += ".sig"
	u.RawPath = ""
	return u.String(), nil
}

// ProductFromURL is the product a manifest at manifestURL must name: the
// first segment of its path when the path has more than one
// ("https://dist.inference.sh/engine/channels/canary.json" is "engine"),
// otherwise "".
func ProductFromURL(manifestURL string) string {
	u, err := url.Parse(manifestURL)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[0]
}

// parseSignatures reads a .sig file: one base64 signature per line, blank
// lines and lines starting with '#' ignored.
func parseSignatures(data []byte) ([][]byte, error) {
	var sigs [][]byte
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return nil, fmt.Errorf("%w: malformed signature line", ErrBadSignature)
		}
		sigs = append(sigs, sig)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if len(sigs) == 0 {
		return nil, fmt.Errorf("%w: signature file is empty", ErrBadSignature)
	}
	return sigs, nil
}

// VerifyManifest checks that sigFile holds a signature of manifest by one of
// keys and that the manifest names product.
func VerifyManifest(manifest, sigFile []byte, keys []ed25519.PublicKey, product string) error {
	if len(keys) == 0 {
		return fmt.Errorf("%w: no trusted keys", ErrBadSignature)
	}
	sigs, err := parseSignatures(sigFile)
	if err != nil {
		return err
	}
	ok := false
	for _, sig := range sigs {
		for _, k := range keys {
			if ed25519.Verify(k, manifest, sig) {
				ok = true
				break
			}
		}
		if ok {
			break
		}
	}
	if !ok {
		return ErrBadSignature
	}

	var signed struct {
		Product string `json:"product"`
	}
	if err := json.Unmarshal(manifest, &signed); err != nil {
		return fmt.Errorf("parse signed manifest: %w", err)
	}
	if signed.Product != product {
		return fmt.Errorf("%w: manifest is for product %q, fetched as %q", ErrBadSignature, signed.Product, product)
	}
	return nil
}
