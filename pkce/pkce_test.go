package pkce

import (
	"regexp"
	"testing"
)

var unreservedPKCE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func TestGeneratePKCE_ShapeAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		p := GeneratePKCE()
		if len(p.Verifier) < 43 || len(p.Verifier) > 128 {
			t.Fatalf("verifier length %d out of spec range 43-128", len(p.Verifier))
		}
		if !unreservedPKCE.MatchString(p.Verifier) {
			t.Fatalf("verifier contains reserved chars: %q", p.Verifier)
		}
		if !unreservedPKCE.MatchString(p.Challenge) {
			t.Fatalf("challenge contains reserved chars: %q", p.Challenge)
		}
		if seen[p.Verifier] {
			t.Fatal("verifier collision — entropy too low")
		}
		seen[p.Verifier] = true
		if got := PKCEChallengeFromVerifier(p.Verifier); got != p.Challenge {
			t.Fatalf("challenge mismatch: got %q want %q", got, p.Challenge)
		}
	}
}
