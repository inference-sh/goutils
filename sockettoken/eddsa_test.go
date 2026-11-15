package sockettoken

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func mustDerive(t *testing.T, secrets ...string) SigningKeys {
	t.Helper()
	k, err := DeriveSigningKeys(secrets...)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var (
	secretA = strings.Repeat("A", 32)
	secretB = strings.Repeat("B", 32)
)

func TestDeriveSigningKeys(t *testing.T) {
	a1, a2 := mustDerive(t, secretA), mustDerive(t, secretA)
	if !a1[0].Equal(a2[0]) {
		t.Fatal("derivation is not deterministic")
	}
	b := mustDerive(t, secretB)
	if a1[0].Equal(b[0]) {
		t.Fatal("two secrets derived the same key")
	}
	both := mustDerive(t, secretA, "", secretB, secretA)
	if len(both) != 2 || !both[0].Equal(a1[0]) || !both[1].Equal(b[0]) {
		t.Fatalf("got %d keys, want A then B", len(both))
	}
	// The derived key is not the HS256 key: an HS256 secret equal to the
	// derivation secret does not give the Ed25519 seed.
	if string(a1[0].Seed()) == secretA {
		t.Fatal("seed is the secret")
	}
	if _, err := DeriveSigningKeys("", ""); err == nil {
		t.Error("derived from nothing")
	}
	if _, err := DeriveSigningKeys("short"); err == nil {
		t.Error("accepted a short secret")
	}
}

// RFC 8037 appendix A.3: the thumbprint of the example key.
func TestKeyID_RFC8037(t *testing.T) {
	pub, _ := ParsePublicKeys("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if len(pub) != 1 || pub[0].ID != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("got %+v", pub)
	}
}

func TestJWKS_RoundTrip(t *testing.T) {
	keys := mustDerive(t, secretA, secretB)
	got, err := ParseJWKS(keys.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	want := keys.Public()
	if len(got) != 2 || got[0].ID != want[0].ID || !got[1].Key.Equal(want[1].Key) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// The same document is accepted from configuration.
	if cfg, err := ParsePublicKeys(string(keys.JWKS())); err != nil || len(cfg) != 2 {
		t.Fatalf("config JWKS: %d keys, %v", len(cfg), err)
	}
	if _, err := ParseJWKS([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + b64(want[0].Key) + `","kid":"wrong"}]}`)); err == nil {
		t.Error("accepted a kid that is not the thumbprint")
	}
	if _, err := ParsePublicKeys("not-a-key"); err == nil {
		t.Error("accepted a malformed key")
	}
	if k, err := ParsePublicKeys(""); err != nil || k != nil {
		t.Errorf("empty config: %v %v", k, err)
	}
}

func TestVerifier_EdDSA(t *testing.T) {
	keys := mustDerive(t, secretA)
	v := Verifier{Keys: NewKeySet("", keys.Public())}
	want := Grant{Socket: "socket_1", Role: RoleWorker, Relay: relayURL}
	raw, err := keys.Issue(want, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(relayURL, raw)
	if err != nil || got != want {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := keys.Issue(Grant{Socket: "s", Role: RoleClient}, time.Minute); err == nil {
		t.Error("issued without a relay")
	}
}

func TestVerifier_Refuses(t *testing.T) {
	keys := mustDerive(t, secretA)
	other := mustDerive(t, secretB)
	grant := Grant{Socket: "socket_1", Role: RoleClient, Relay: relayURL}
	issue := func(k SigningKeys, g Grant, ttl time.Duration) string {
		t.Helper()
		raw, err := k.Issue(g, ttl)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// A token signed by an unpublished key but claiming a published kid.
	forged, err := func() (string, error) {
		tok, err := newGrantToken(jwt.SigningMethodEdDSA, grant, time.Minute)
		if err != nil {
			return "", err
		}
		tok.Header["kid"] = keys.Public()[0].ID
		return tok.SignedString(other[0])
	}()
	if err != nil {
		t.Fatal(err)
	}
	noKid, _ := func() (string, error) {
		tok, _ := newGrantToken(jwt.SigningMethodEdDSA, grant, time.Minute)
		return tok.SignedString(keys[0])
	}()
	// HS256 signed with the Ed25519 public key's bytes: the alg-confusion attempt.
	confused, _ := func() (string, error) {
		tok, _ := newGrantToken(jwt.SigningMethodHS256, grant, time.Minute)
		tok.Header["kid"] = keys.Public()[0].ID
		return tok.SignedString([]byte(keys.Public()[0].Key))
	}()
	hs, _ := Issue(testKeys, grant, time.Minute)

	cases := map[string]string{
		"expired":           issue(keys, grant, -time.Minute),
		"another relay":     issue(keys, Grant{Socket: "socket_1", Role: RoleClient, Relay: "wss://other.example.com"}, time.Minute),
		"unpublished key":   issue(other, grant, time.Minute),
		"forged kid":        forged,
		"no kid":            noKid,
		"alg confusion":     confused,
		"hs256 not enabled": hs,
		"garbage":           "not-a-token",
	}
	v := Verifier{Keys: NewKeySet("", keys.Public())}
	for name, raw := range cases {
		if _, err := v.Verify(relayURL, raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

// The release in which relays take both formats.
func TestVerifier_LegacyHS256(t *testing.T) {
	keys := mustDerive(t, secretA)
	grant := Grant{Socket: "socket_1", Role: RoleClient, Relay: relayURL}
	hs, _ := Issue(testKeys, grant, time.Minute)
	ed, _ := keys.Issue(grant, time.Minute)
	both := Verifier{Keys: NewKeySet("", keys.Public()), LegacyHS256: testKeys}
	for name, raw := range map[string]string{"hs256": hs, "eddsa": ed} {
		if _, err := both.Verify(relayURL, raw); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	// HS256 only, no public keys yet: HS256 still works, EdDSA does not.
	legacy := Verifier{LegacyHS256: testKeys}
	if _, err := legacy.Verify(relayURL, hs); err != nil {
		t.Errorf("hs256 refused: %v", err)
	}
	if _, err := legacy.Verify(relayURL, ed); !errors.Is(err, ErrInvalid) {
		t.Errorf("eddsa without keys: %v", err)
	}
	// The legacy Verify never takes EdDSA.
	if _, err := Verify(testKeys, relayURL, ed); !errors.Is(err, ErrInvalid) {
		t.Errorf("legacy Verify took eddsa: %v", err)
	}
}

func jwksServer(t *testing.T, doc *atomic.Value, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != KeysPath {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(doc.Load().([]byte))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A rotation: the API starts signing with a key the relay has not fetched. The
// first token naming it fetches the set once; a key no longer published stops
// verifying after the next fetch.
func TestKeySet_FetchesOnUnknownKid(t *testing.T) {
	oldKeys := mustDerive(t, secretA)
	rotated := mustDerive(t, secretB, secretA)
	var doc atomic.Value
	var hits atomic.Int32
	doc.Store(oldKeys.JWKS())
	srv := jwksServer(t, &doc, &hits)

	set := NewKeySet(KeysURL(srv.URL+"/"), nil)
	if err := set.Refresh(context.Background()); err != nil || set.Len() != 1 {
		t.Fatalf("refresh: %d keys, %v", set.Len(), err)
	}
	v := Verifier{Keys: set}
	grant := Grant{Socket: "socket_1", Role: RoleClient, Relay: relayURL}

	doc.Store(rotated.JWKS())
	set.lastFetch = time.Time{} // past minRefetch
	raw, _ := rotated.Issue(grant, time.Minute)
	if _, err := v.Verify(relayURL, raw); err != nil {
		t.Fatalf("new key refused: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("fetched %d times, want 2", hits.Load())
	}

	// Unknown kids within minRefetch do not fetch again.
	stranger := mustDerive(t, strings.Repeat("C", 32))
	for range 5 {
		raw, _ := stranger.Issue(grant, time.Minute)
		if _, err := v.Verify(relayURL, raw); !errors.Is(err, ErrInvalid) {
			t.Fatalf("stranger accepted: %v", err)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("fetched %d times, want 2", hits.Load())
	}

	// The old key retires: after the next fetch its tokens are refused.
	doc.Store(mustDerive(t, secretB).JWKS())
	if err := set.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	old, _ := oldKeys.Issue(grant, time.Minute)
	if _, err := v.Verify(relayURL, old); !errors.Is(err, ErrInvalid) {
		t.Fatalf("retired key accepted: %v", err)
	}
}

// Static keys from configuration verify with the API unreachable, and survive
// fetches.
func TestKeySet_StaticFallback(t *testing.T) {
	keys := mustDerive(t, secretA)
	set := NewKeySet("http://127.0.0.1:1"+KeysPath, keys.Public())
	if err := set.Refresh(context.Background()); err == nil {
		t.Fatal("fetch from a closed port succeeded")
	}
	raw, _ := keys.Issue(Grant{Socket: "s", Role: RoleWorker, Relay: relayURL}, time.Minute)
	if _, err := (Verifier{Keys: set}).Verify(relayURL, raw); err != nil {
		t.Fatalf("static key refused: %v", err)
	}
}

func TestKeySet_BadResponseKeepsKeys(t *testing.T) {
	keys := mustDerive(t, secretA)
	var doc atomic.Value
	var hits atomic.Int32
	doc.Store(keys.JWKS())
	srv := jwksServer(t, &doc, &hits)
	set := NewKeySet(KeysURL(srv.URL), nil)
	if err := set.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	doc.Store([]byte("not json"))
	if err := set.Refresh(context.Background()); err == nil {
		t.Fatal("accepted a malformed set")
	}
	if set.Len() != 1 {
		t.Fatalf("a failed fetch dropped keys: %d", set.Len())
	}
}

func TestIssuer(t *testing.T) {
	keys := mustDerive(t, secretA)
	grant := Grant{Socket: "socket_1", Role: RoleClient, Relay: relayURL}
	alg := func(i Issuer) string {
		t.Helper()
		raw, err := i.Issue(grant, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		tok, _, err := jwt.NewParser().ParseUnverified(raw, &claims{})
		if err != nil {
			t.Fatal(err)
		}
		return tok.Method.Alg()
	}
	if got := alg(Issuer{LegacyHS256: testKeys}); got != "HS256" {
		t.Errorf("legacy issuer signed %s", got)
	}
	if got := alg(Issuer{Signing: keys, LegacyHS256: testKeys}); got != "EdDSA" {
		t.Errorf("EdDSA issuer signed %s", got)
	}
	if (Issuer{}).Ready() {
		t.Error("an issuer without keys is ready")
	}
	if _, err := (Issuer{}).Issue(grant, time.Minute); err == nil {
		t.Error("issued without keys")
	}
}
