package contentsafety

import (
	"encoding/json"
	"strings"
	"testing"
)

// A masked secret matches no vendor pattern, so only the field name identifies
// it. Committed cassettes made this concrete: 74 secrets' last four characters
// were recorded because masked_value looked like ordinary text.
func TestCleanJSON_redactsByFieldName(t *testing.T) {
	in := `{"key":"CAPTIONS_KEY","masked_value":"••••••••72ae","access_token":"opaque-blob","id":"abc123"}`

	out, findings := CleanJSON(json.RawMessage(in), Credentials)

	got := string(out)
	for _, secret := range []string{"72ae", "opaque-blob"} {
		if strings.Contains(got, secret) {
			t.Errorf("secret %q survived: %s", secret, got)
		}
	}
	// The secret's name and the record's id are what make the fixture useful.
	for _, keep := range []string{"CAPTIONS_KEY", "abc123"} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q should be preserved: %s", keep, got)
		}
	}
	if len(findings) != 2 {
		t.Errorf("want 2 findings, got %d: %v", len(findings), findings)
	}
}

// "key" and "value" are ordinary field names throughout belt's payloads.
func TestCleanJSON_leavesAmbiguousFieldNames(t *testing.T) {
	in := `{"key":"MY_SECRET_NAME","value":null,"nodes":{"tts":{"value":"merhaba"}}}`

	out, _ := CleanJSON(json.RawMessage(in), Credentials)

	for _, keep := range []string{"MY_SECRET_NAME", "merhaba"} {
		if !strings.Contains(string(out), keep) {
			t.Errorf("%q was redacted but is not secret material: %s", keep, out)
		}
	}
}

// The cassette case: redact a masked secret inside a raw byte fragment without
// decoding it, because the fragment's boundaries are what replay reproduces.
func TestRedactSecretFields(t *testing.T) {
	in := `{"key":"CAPTIONS_KEY","masked_value":"••••••••72ae","maskedValue":"••••••••x2pL",` +
		`"access_token":"opaque","id":"abc123","value":"merhaba"}`

	out, findings := RedactSecretFields(in)

	for _, gone := range []string{"72ae", "x2pL", "opaque"} {
		if strings.Contains(out, gone) {
			t.Errorf("%q survived: %s", gone, out)
		}
	}
	// The secret's name, the id, and ordinary content stay: they are what make
	// the fixture worth keeping.
	for _, keep := range []string{"CAPTIONS_KEY", "abc123", "merhaba"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q should be preserved: %s", keep, out)
		}
	}
	if len(findings) != 3 {
		t.Errorf("want 3 findings, got %d", len(findings))
	}
	if !json.Valid([]byte(out)) {
		t.Errorf("output is not valid JSON: %s", out)
	}
}

func TestRedactSecretFields_noSecretsIsUntouched(t *testing.T) {
	in := `{"id":"abc","name":"thing","value":null}`
	if out, findings := RedactSecretFields(in); out != in || findings != nil {
		t.Errorf("unchanged input was rewritten: %s %v", out, findings)
	}
}

// A fragment that is not JSON at all must survive intact.
func TestRedactSecretFields_plainTextUntouched(t *testing.T) {
	in := "the token is a concept, not a field"
	if out, _ := RedactSecretFields(in); out != in {
		t.Errorf("prose was rewritten: %q", out)
	}
}
