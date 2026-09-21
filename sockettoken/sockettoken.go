// Package sockettoken is what the API and a socket relay agree on: the
// credential each end of a socket presents to the relay, and the report the
// relay sends back about what happened to the socket.
//
// The API issues one token per end when it opens a socket; the relay verifies
// them and pairs the ends. Issuer and verifier are separate services, so the
// formats live here, where both can import their one definition.
//
// A token is an HS256 JWT signed with a secret only the API and the relays
// hold. That secret signs nothing else: a relay that leaks it can forge socket
// tokens and nothing more. The audience is the relay the API chose for the
// task, so a token is good at that relay only.
package sockettoken

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Role is which end of the socket the bearer is.
type Role string

const (
	// RoleClient is the caller: a browser, an SDK, a telephony bridge.
	RoleClient Role = "client"
	// RoleWorker is the engine worker running the task.
	RoleWorker Role = "worker"
)

func (r Role) valid() bool { return r == RoleClient || r == RoleWorker }

// Grant is what a token states: the bearer may join this socket, as this end,
// at this relay.
type Grant struct {
	Socket string
	Role   Role
	Relay  string // the relay's public base URL, e.g. wss://relay.inference.sh
}

// ErrInvalid wraps every verification failure.
var ErrInvalid = errors.New("invalid socket token")

// minKeyBytes is the shortest secret accepted: the HS256 output size.
const minKeyBytes = 32

// Keys is the signing secret and any older secrets still in rotation. The
// first signs; all verify.
type Keys [][]byte

// ParseKeys reads a comma-separated list of secrets, newest first.
func ParseKeys(s string) (Keys, error) {
	var keys Keys
	for _, k := range strings.Split(s, ",") {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if len(k) < minKeyBytes {
			return nil, fmt.Errorf("socket signing key is %d bytes, need at least %d", len(k), minKeyBytes)
		}
		keys = append(keys, []byte(k))
	}
	if len(keys) == 0 {
		return nil, errors.New("no socket signing key configured")
	}
	return keys, nil
}

// verification offers every key still in rotation to the JWT parser.
func (keys Keys) verification(*jwt.Token) (any, error) {
	set := jwt.VerificationKeySet{Keys: make([]jwt.VerificationKey, 0, len(keys))}
	for _, k := range keys {
		set.Keys = append(set.Keys, k)
	}
	return set, nil
}

// SocketURL is the address both ends dial for a socket at a relay.
func SocketURL(relay, socket string) string {
	return strings.TrimRight(relay, "/") + "/sockets/" + socket
}

// claims is the wire form. The socket is the subject; the relay is the audience.
type claims struct {
	jwt.RegisteredClaims
	Role Role `json:"role"`
}

// Issue signs a grant that expires after ttl.
func Issue(keys Keys, g Grant, ttl time.Duration) (string, error) {
	if len(keys) == 0 {
		return "", errors.New("no socket signing key configured")
	}
	if g.Socket == "" || g.Relay == "" || !g.Role.valid() {
		return "", fmt.Errorf("incomplete socket grant: %+v", g)
	}
	now := time.Now()
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   g.Socket,
			Audience:  jwt.ClaimStrings{g.Relay},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Role: g.Role,
	})
	return t.SignedString(keys[0])
}

// leeway absorbs clock drift between the API host and a relay host.
const leeway = 5 * time.Second

// Verify checks a token presented at relay and returns the grant it carries.
func Verify(keys Keys, relay, raw string) (Grant, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithAudience(relay),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
	)
	var c claims
	if _, err := parser.ParseWithClaims(raw, &c, keys.verification); err != nil {
		return Grant{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if c.Subject == "" || !c.Role.valid() {
		return Grant{}, fmt.Errorf("%w: incomplete grant", ErrInvalid)
	}
	return Grant{Socket: c.Subject, Role: c.Role, Relay: relay}, nil
}
