package sockettoken

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// KeysPath is where the API publishes the public keys socket tokens are
// signed with, as a JWK set. Relays fetch it from the API base URL.
const KeysPath = "/relay/socket-keys"

// KeysURL is the public key set's address at an API base URL.
func KeysURL(apiBase string) string {
	return strings.TrimRight(apiBase, "/") + KeysPath
}

// deriveLabel separates the socket signing key from anything else derived
// from the same API secret. Changing it changes every key.
const deriveLabel = "inference.sh/sockettoken/ed25519/v1"

// SigningKeys is the API's Ed25519 keys, newest first. The first signs; all
// are published, so a token signed by a key on its way out still verifies.
type SigningKeys []ed25519.PrivateKey

// DeriveSigningKeys derives one signing key per secret, newest first, with
// HKDF-SHA256 under a label of its own. The API passes secrets only it holds,
// so the keys need no storage, distribution or rotation of their own: they
// rotate when the secret does. Empty and repeated secrets are skipped.
func DeriveSigningKeys(secrets ...string) (SigningKeys, error) {
	var keys SigningKeys
	seen := map[string]bool{}
	for _, s := range secrets {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		if len(s) < minKeyBytes {
			return nil, fmt.Errorf("socket key secret is %d bytes, need at least %d", len(s), minKeyBytes)
		}
		seed, err := hkdf.Key(sha256.New, []byte(s), nil, deriveLabel, ed25519.SeedSize)
		if err != nil {
			return nil, err
		}
		keys = append(keys, ed25519.NewKeyFromSeed(seed))
	}
	if len(keys) == 0 {
		return nil, errors.New("no socket key secret configured")
	}
	return keys, nil
}

// PublicKey is a verification key and its id, the RFC 7638 JWK thumbprint.
type PublicKey struct {
	ID  string
	Key ed25519.PublicKey
}

// KeyID is the RFC 7638 thumbprint of an Ed25519 public key. It is what a
// token's kid names, so a key's id never has to be configured.
func KeyID(pub ed25519.PublicKey) string {
	// Members in lexicographic order, no whitespace (RFC 7638 section 3).
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + b64(pub) + `"}`))
	return b64(sum[:])
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Public returns the keys' public halves, newest first.
func (k SigningKeys) Public() []PublicKey {
	out := make([]PublicKey, 0, len(k))
	for _, priv := range k {
		pub := priv.Public().(ed25519.PublicKey)
		out = append(out, PublicKey{ID: KeyID(pub), Key: pub})
	}
	return out
}

// jwk is one Ed25519 key in a JWK set (RFC 8037).
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// JWKS is the document the API serves at KeysPath.
func (k SigningKeys) JWKS() []byte {
	set := jwkSet{Keys: []jwk{}}
	for _, p := range k.Public() {
		set.Keys = append(set.Keys, jwk{Kty: "OKP", Crv: "Ed25519", X: b64(p.Key), Kid: p.ID, Alg: "EdDSA", Use: "sig"})
	}
	b, _ := json.Marshal(set) // strings only; cannot fail
	return b
}

// ParseJWKS reads a JWK set and returns its Ed25519 keys. A key whose kid is
// not its thumbprint is refused: tokens name keys by thumbprint.
func ParseJWKS(b []byte) ([]PublicKey, error) {
	var set jwkSet
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, fmt.Errorf("socket keys: %w", err)
	}
	var out []PublicKey
	for _, k := range set.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue
		}
		pub, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("socket keys: malformed key %q", k.Kid)
		}
		id := KeyID(pub)
		if k.Kid != "" && k.Kid != id {
			return nil, fmt.Errorf("socket keys: kid %q is not the key's thumbprint %q", k.Kid, id)
		}
		out = append(out, PublicKey{ID: id, Key: pub})
	}
	return out, nil
}

// ParsePublicKeys reads public keys from configuration: a JWK set as the API
// serves it, or a comma-separated list of base64url Ed25519 public keys (a
// JWK's x). Empty is no keys.
func ParsePublicKeys(s string) ([]PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if strings.HasPrefix(s, "{") {
		return ParseJWKS([]byte(s))
	}
	var out []PublicKey
	for _, x := range strings.Split(s, ",") {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		pub, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(x, "="))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("socket public key %q is not a base64url Ed25519 key", x)
		}
		out = append(out, PublicKey{ID: KeyID(pub), Key: pub})
	}
	return out, nil
}

// Issue signs a grant with the newest key, naming it in the kid header.
func (k SigningKeys) Issue(g Grant, ttl time.Duration) (string, error) {
	if len(k) == 0 {
		return "", errors.New("no socket signing key configured")
	}
	t, err := newGrantToken(jwt.SigningMethodEdDSA, g, ttl)
	if err != nil {
		return "", err
	}
	t.Header["kid"] = KeyID(k[0].Public().(ed25519.PublicKey))
	return t.SignedString(k[0])
}

// KeySet is the public keys a relay verifies socket tokens with: the ones
// from configuration, which it always keeps, and the ones the API publishes,
// fetched from URL. A token naming a key the set does not hold triggers a
// fetch, at most one per minRefetch, so a key the API starts signing with is
// picked up on first use.
type KeySet struct {
	url    string
	client *http.Client

	mu      sync.RWMutex
	static  []PublicKey
	fetched []PublicKey

	fetchMu   sync.Mutex
	lastFetch time.Time
}

// minRefetch bounds fetches triggered by unknown kids: a stream of tokens
// with made-up kids costs one fetch per interval.
const minRefetch = 10 * time.Second

// fetchTimeout bounds one fetch of the key set.
const fetchTimeout = 5 * time.Second

// maxKeysBody bounds the key set document.
const maxKeysBody = 64 << 10

// NewKeySet returns a set holding static and, when url is set, whatever the
// API publishes there. It does not fetch; call Refresh or Run.
func NewKeySet(url string, static []PublicKey) *KeySet {
	return &KeySet{url: url, static: static, client: &http.Client{Timeout: fetchTimeout}}
}

// URL is where the set fetches keys from; empty when it only has static keys.
func (s *KeySet) URL() string { return s.url }

// Len is how many keys the set holds now.
func (s *KeySet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.static) + len(s.fetched)
}

// Refresh fetches the published keys and replaces the fetched ones, so a key
// the API stopped publishing stops verifying. On error the set is unchanged.
func (s *KeySet) Refresh(ctx context.Context) error {
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	return s.refreshLocked(ctx)
}

func (s *KeySet) refreshLocked(ctx context.Context) error {
	if s.url == "" {
		return nil
	}
	s.lastFetch = time.Now()
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("socket keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("socket keys: %s answered %d", s.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeysBody))
	if err != nil {
		return fmt.Errorf("socket keys: %w", err)
	}
	keys, err := ParseJWKS(body)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.fetched = keys
	s.mu.Unlock()
	return nil
}

// Run refreshes the set every interval until ctx ends, calling onErr (if set)
// with each failed fetch.
func (s *KeySet) Run(ctx context.Context, every time.Duration, onErr func(error)) {
	if s.url == "" {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Refresh(ctx); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}

func (s *KeySet) find(kid string) (ed25519.PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, set := range [][]PublicKey{s.static, s.fetched} {
		for _, k := range set {
			if k.ID == kid {
				return k.Key, true
			}
		}
	}
	return nil, false
}

// lookup finds kid, fetching once when it is unknown and the last fetch is
// older than minRefetch.
func (s *KeySet) lookup(kid string) (ed25519.PublicKey, bool) {
	if k, ok := s.find(kid); ok {
		return k, true
	}
	if s.url == "" {
		return nil, false
	}
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	// Another caller may have fetched while this one waited.
	if k, ok := s.find(kid); ok {
		return k, true
	}
	if time.Since(s.lastFetch) < minRefetch {
		return nil, false
	}
	if err := s.refreshLocked(context.Background()); err != nil {
		return nil, false
	}
	return s.find(kid)
}

// Verifier checks socket tokens at a relay. Keys verifies EdDSA tokens.
// LegacyHS256, when set, also accepts HS256 tokens signed with the shared
// secret: for the release in which the API still issues them, and to be left
// empty once it does not, so a relay's secret can no longer mint tokens.
type Verifier struct {
	Keys        *KeySet
	LegacyHS256 Keys
}

// Verify checks a token presented at relay and returns the grant it carries.
func (v Verifier) Verify(relay, raw string) (Grant, error) {
	methods := []string{jwt.SigningMethodEdDSA.Alg()}
	if len(v.LegacyHS256) > 0 {
		methods = append(methods, jwt.SigningMethodHS256.Alg())
	}
	return verifyGrant(relay, raw, methods, v.keyfunc)
}

func (v Verifier) keyfunc(t *jwt.Token) (any, error) {
	switch t.Method.Alg() {
	case jwt.SigningMethodEdDSA.Alg():
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token names no key")
		}
		if v.Keys == nil {
			return nil, errors.New("no socket public keys configured")
		}
		k, ok := v.Keys.lookup(kid)
		if !ok {
			return nil, fmt.Errorf("unknown key %q", kid)
		}
		return k, nil
	case jwt.SigningMethodHS256.Alg():
		return v.LegacyHS256.verification(t)
	}
	return nil, fmt.Errorf("unexpected method %s", t.Method.Alg())
}

// Issuer is what the API signs socket tokens with: EdDSA with Signing when it
// is set, else HS256 with LegacyHS256, the format before EdDSA. The API sets
// Signing once every relay verifies EdDSA; the next release drops HS256.
type Issuer struct {
	Signing     SigningKeys
	LegacyHS256 Keys
}

// Ready reports whether the issuer has a key to sign with.
func (i Issuer) Ready() bool { return len(i.Signing) > 0 || len(i.LegacyHS256) > 0 }

// Issue signs a grant that expires after ttl.
func (i Issuer) Issue(g Grant, ttl time.Duration) (string, error) {
	if len(i.Signing) > 0 {
		return i.Signing.Issue(g, ttl)
	}
	return Issue(i.LegacyHS256, g, ttl)
}
