package sockettoken

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Event is a point in a socket's life the relay reports.
type Event string

const (
	// EventPaired: both ends are connected and frames flow.
	EventPaired Event = "paired"
	// EventEnded: the socket is over, whether or not it was ever paired.
	EventEnded Event = "ended"
)

// Outcome is why a socket ended.
type Outcome string

const (
	OutcomeClientClosed Outcome = "client_closed"
	OutcomeWorkerClosed Outcome = "worker_closed"
	OutcomeUnpaired     Outcome = "unpaired"  // the other end never came
	OutcomeDrained      Outcome = "drained"   // the relay was restarting
	OutcomeAbandoned    Outcome = "abandoned" // the only end failed its upgrade
)

// Report is what a relay tells the API about one socket. Reports are facts
// after the event: the relay never waits for the API, and the API never
// steers a live socket through them.
type Report struct {
	Socket string    `json:"socket"`
	Event  Event     `json:"event"`
	At     time.Time `json:"at"`

	// The rest is set on EventEnded.
	Outcome      Outcome `json:"outcome,omitempty"`
	Paired       bool    `json:"paired,omitempty"`
	CloseCode    int     `json:"close_code,omitempty"`
	CloseReason  string  `json:"close_reason,omitempty"`
	ClientFrames int64   `json:"client_frames,omitempty"`
	ClientBytes  int64   `json:"client_bytes,omitempty"`
	WorkerFrames int64   `json:"worker_frames,omitempty"`
	WorkerBytes  int64   `json:"worker_bytes,omitempty"`
}

// reportAudience is fixed: a report token is good for reporting and nothing
// else, and a socket token's audience is a relay URL, so neither passes as
// the other.
const reportAudience = "inference.sh/socket-report"

// IssueReportToken signs the credential a relay sends with its reports. The
// subject is the relay's public URL; the API accepts a report only for
// sockets it assigned to that relay.
func IssueReportToken(keys Keys, relay string, ttl time.Duration) (string, error) {
	if len(keys) == 0 {
		return "", errors.New("no socket signing key configured")
	}
	if relay == "" {
		return "", errors.New("report token needs the relay's public URL")
	}
	now := time.Now()
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   relay,
		Audience:  jwt.ClaimStrings{reportAudience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	})
	return t.SignedString(keys[0])
}

// VerifyReportToken returns the public URL of the relay that signed raw.
func VerifyReportToken(keys Keys, raw string) (relay string, err error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithAudience(reportAudience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
	)
	var c jwt.RegisteredClaims
	if _, err := parser.ParseWithClaims(raw, &c, keys.verification); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if c.Subject == "" {
		return "", fmt.Errorf("%w: no relay", ErrInvalid)
	}
	return c.Subject, nil
}
