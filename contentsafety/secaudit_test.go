package contentsafety

import (
	"encoding/json"
	"strings"
	"testing"
)

// Field names that mean a credential under the spellings third-party payloads
// use: bearer_token, apikey, and the acronym form APIKey.
func TestClassifyKey_credentialAliases(t *testing.T) {
	for _, key := range []string{"bearer_token", "bearerToken", "apikey", "APIKey", "ApiKey", "apiKey", "X-API-Key", "x-api-key"} {
		if got := ClassifyKey(nil, key); got != ClassSecret {
			t.Errorf("ClassifyKey(%q) = %v, want ClassSecret", key, got)
		}
	}
	in := `{"APIKey":"opaque-one","bearer_token":"opaque-two","id":"abc123"}`
	out, _ := CleanJSON(json.RawMessage(in), Credentials)
	for _, gone := range []string{"opaque-one", "opaque-two"} {
		if strings.Contains(string(out), gone) {
			t.Errorf("%q survived: %s", gone, out)
		}
	}
	if !strings.Contains(string(out), "abc123") {
		t.Errorf("id was redacted: %s", out)
	}
}

// Every PEM private key header, not only RSA and PKCS#8.
func TestPrivateKeyHeaders(t *testing.T) {
	for _, kind := range []string{"", "RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED "} {
		pem := "-----BEGIN " + kind + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END " + kind + "PRIVATE KEY-----"
		if got := Redact("key:\n" + pem); strings.Contains(got, "MIIEvQIBADAN") {
			t.Errorf("%sPRIVATE KEY body survived Redact: %s", kind, got)
		}
		if got, _ := Clean("key:\n"+pem, Credentials); strings.Contains(got, "MIIEvQIBADAN") {
			t.Errorf("%sPRIVATE KEY body survived Clean: %s", kind, got)
		}
		if !findingIDs(Detect(pem, HiddenContent).Findings)["INF-SEC-009"] {
			t.Errorf("%sPRIVATE KEY not detected by INF-SEC-009", kind)
		}
	}
	pgp := "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBGabcdefBCADExampleBody\n-----END PGP PRIVATE KEY BLOCK-----"
	if got := Redact(pgp); strings.Contains(got, "lQOYBGabcdef") {
		t.Errorf("PGP private key block survived Redact: %s", got)
	}
	// A public key or a certificate is not a secret.
	pub := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQY\n-----END PUBLIC KEY-----"
	if got := Redact(pub); got != pub {
		t.Errorf("public key was rewritten: %s", got)
	}
}

// A session token (two ULIDs, no prefix) is only reported, because the bare
// shape is also a hash's; after "Bearer" it is a credential and is rewritten.
func TestClean_sessionTokenInBearerContext(t *testing.T) {
	token := "01hzy3v9k2m4n6p8q0r1s2t3v4" + "01hzy3v9k2m4n6p8q0r1s2t3v5"
	if len(token) != 52 {
		t.Fatalf("token is %d characters", len(token))
	}

	out, findings := Clean("curl -H 'Authorization: Bearer "+token+"' https://api.inference.sh/me", Credentials)
	if strings.Contains(out, token) {
		t.Errorf("bearer session token survived: %s", out)
	}
	if !findingIDs(findings)["INF-CRED-006"] {
		t.Errorf("expected INF-CRED-006, got %v", findings)
	}
	if !strings.Contains(out, "https://api.inference.sh/me") {
		t.Errorf("the rest of the line was consumed: %s", out)
	}

	bare := "sha256 (base32): " + token
	out, _ = Clean(bare, Credentials)
	if out != bare {
		t.Errorf("a bare 52-character string was rewritten: %s", out)
	}
	if !findingIDs(Detect(bare, Credentials).Findings)["INF-CRED-002"] {
		t.Errorf("a bare token is still reported")
	}
}
