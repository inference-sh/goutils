package sockettoken

import (
	"errors"
	"testing"
	"time"
)

func TestReportToken_RoundTrip(t *testing.T) {
	raw, err := IssueReportToken(testKeys, relayURL, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := VerifyReportToken(testKeys, raw)
	if err != nil || relay != relayURL {
		t.Fatalf("got (%q, %v), want %q", relay, err, relayURL)
	}
}

// A socket token and a report token are signed with the same keys. Neither
// may pass as the other.
func TestReportAndSocketTokensDoNotCross(t *testing.T) {
	socket, err := Issue(testKeys, Grant{Socket: "socket_1", Role: RoleWorker, Relay: relayURL}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReportToken(testKeys, socket); !errors.Is(err, ErrInvalid) {
		t.Errorf("socket token accepted as a report token: %v", err)
	}

	report, err := IssueReportToken(testKeys, relayURL, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(testKeys, relayURL, report); !errors.Is(err, ErrInvalid) {
		t.Errorf("report token accepted as a socket token: %v", err)
	}
}

func TestReportToken_RefusesExpired(t *testing.T) {
	raw, err := IssueReportToken(testKeys, relayURL, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReportToken(testKeys, raw); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}
