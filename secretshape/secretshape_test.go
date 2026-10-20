package secretshape

import (
	"strings"
	"testing"
)

func TestRedact_knownShapes(t *testing.T) {
	cases := []string{
		"sk-" + strings.Repeat("a", 40),
		"sk-ant-" + strings.Repeat("b", 40),
		"sk_live_" + strings.Repeat("c", 24),
		"ghp_" + strings.Repeat("d", 36),
		"github_pat_" + strings.Repeat("e", 30),
		"glpat-" + strings.Repeat("f", 20),
		"xoxb-" + strings.Repeat("1", 12),
		"AKIA" + strings.Repeat("Q", 16),
		"AIza" + strings.Repeat("g", 35),
		"ya29." + strings.Repeat("h", 30),
		"infrt-" + strings.Repeat("i", 20),
		"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----",
	}
	for _, v := range cases {
		out, n := Redact("before "+v+" after", "")
		if n != 1 || strings.Contains(out, v) || !strings.Contains(out, Placeholder) {
			t.Errorf("%q: got %q (%d)", v, out, n)
		}
	}
	out, n := Redact(`Authorization: Bearer `+strings.Repeat("t", 32), "")
	if n != 1 || out != "Authorization: Bearer "+Placeholder {
		t.Errorf("bearer: got %q (%d)", out, n)
	}
}

func TestRedact_ordinaryTextUntouched(t *testing.T) {
	cases := []string{
		"a normal sentence about skiing and skates",
		`{"url":"https://x.example/a.b.c?sig=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"}`, // JWT-like, kept
		"ask-me-anything-" + strings.Repeat("z", 30),                                     // sk- inside a word
		`{"a":"-----BEGIN PRIVATE KEY-----","b":"-----END PRIVATE KEY-----"}`,            // a shape never spans a quote
	}
	for _, v := range cases {
		out, n := Redact(v, "")
		if n != 0 || out != v {
			t.Errorf("%q: got %q (%d)", v, out, n)
		}
	}
}

func TestRedact_customPlaceholder(t *testing.T) {
	out, _ := Redact("AKIA"+strings.Repeat("Q", 16), "***")
	if out != "***" {
		t.Errorf("got %q", out)
	}
}
