package sockettoken

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const relayURL = "wss://relay.example.com"

var testKeys = Keys{[]byte(strings.Repeat("a", 32))}

func TestIssueVerify_RoundTrip(t *testing.T) {
	want := Grant{Socket: "socket_1", Role: RoleWorker, Relay: relayURL}
	raw, err := Issue(testKeys, want, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(testKeys, relayURL, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestVerify_Refuses(t *testing.T) {
	grant := Grant{Socket: "socket_1", Role: RoleClient, Relay: relayURL}
	issue := func(keys Keys, g Grant, ttl time.Duration) string {
		t.Helper()
		raw, err := Issue(keys, g, ttl)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	otherKeys := Keys{[]byte(strings.Repeat("b", 32))}
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   grant.Socket,
			Audience:  jwt.ClaimStrings{relayURL},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
		Role: RoleClient,
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"expired":       issue(testKeys, grant, -time.Minute),
		"another relay": issue(testKeys, Grant{Socket: "socket_1", Role: RoleClient, Relay: "wss://other.example.com"}, time.Minute),
		"another key":   issue(otherKeys, grant, time.Minute),
		"unsigned":      unsigned,
		"garbage":       "not-a-token",
		"empty":         "",
	}
	for name, raw := range cases {
		if _, err := Verify(testKeys, relayURL, raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestVerify_AcceptsRotatedKey(t *testing.T) {
	old := Keys{[]byte(strings.Repeat("o", 32))}
	raw, err := Issue(old, Grant{Socket: "socket_1", Role: RoleClient, Relay: relayURL}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rotated := Keys{testKeys[0], old[0]}
	if _, err := Verify(rotated, relayURL, raw); err != nil {
		t.Fatalf("token signed with a key still in rotation was refused: %v", err)
	}
}

func TestIssue_RefusesIncompleteGrant(t *testing.T) {
	for _, g := range []Grant{
		{Role: RoleClient, Relay: relayURL},
		{Socket: "socket_1", Relay: relayURL},
		{Socket: "socket_1", Role: "admin", Relay: relayURL},
		{Socket: "socket_1", Role: RoleClient},
	} {
		if _, err := Issue(testKeys, g, time.Minute); err == nil {
			t.Errorf("issued a token for %+v", g)
		}
	}
}

func TestParseKeys(t *testing.T) {
	long := strings.Repeat("k", 32)
	keys, err := ParseKeys(" " + long + " , " + long + ",")
	if err != nil || len(keys) != 2 {
		t.Fatalf("got %d keys, err %v", len(keys), err)
	}
	if _, err := ParseKeys("short"); err == nil {
		t.Error("accepted a short key")
	}
	if _, err := ParseKeys(""); err == nil {
		t.Error("accepted an empty list")
	}
}

func TestSocketURL(t *testing.T) {
	if got := SocketURL("wss://relay.example.com/", "socket_1"); got != "wss://relay.example.com/sockets/socket_1" {
		t.Fatal(got)
	}
}
