package strutil

import (
	"strings"
	"testing"
)

func TestIsValidName(t *testing.T) {
	for _, n := range []string{"a", "ok", "my-app", "flux-1-dev", "a1-b2-c3", strings.Repeat("a", MaxNameLength)} {
		if !IsValidName(n) {
			t.Errorf("%q: expected valid", n)
		}
	}
	for _, n := range []string{"", "Bad", "mcp.pipedrive.com", "a_b", "a--b", "-a", "a-", "a b", "a/b", "ünïcode", strings.Repeat("a", MaxNameLength+1)} {
		if IsValidName(n) {
			t.Errorf("%q: expected invalid", n)
		}
	}
}

func TestNormalizeName(t *testing.T) {
	cases := map[string]string{
		"My App":            "my-app",
		"mcp.pipedrive.com": "mcp-pipedrive-com",
		"nil_slice_json":    "nil-slice-json",
		"  Ünïcode  Name ":  "unicode-name",
		"a--b__c":           "a-b-c",
		"---":               "",
		"":                  "",
		"already-valid":     "already-valid",
	}
	for in, want := range cases {
		if got := NormalizeName(in); got != want {
			t.Errorf("NormalizeName(%q) = %q, want %q", in, got, want)
		}
	}
	long := NormalizeName(strings.Repeat("ab-", 30))
	if len(long) > MaxNameLength || !IsValidName(long) || !strings.HasSuffix(long, "ab") {
		t.Errorf("long name not truncated on a hyphen boundary: %q", long)
	}
}
