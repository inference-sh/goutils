// Package relaywire holds the numbers a socket relay and the ends that dial
// it have to agree on. It imports nothing, so an end can share a limit with
// the relay without taking on the relay's dependencies.
package relaywire

import "strconv"

// WaitingFrames is how many frames a relay holds for an end whose peer has
// not arrived yet; past it the relay stops reading that end. An end that
// redials after a relay restart may send again at most this many frames
// without blocking, so a worker remembers no more than this.
const WaitingFrames = 64

// CloseCode is a WebSocket close code the relay and belt put on a sandbox
// port stream (the box's end of one connection to a port) beyond the
// standard ones. Codes 4000-4999 are for applications (RFC 6455 7.4.2).
type CloseCode int

const (
	// CloseStreamRevoked: the relay ended the stream because the access
	// it was opened under was taken back (the port closed, made private,
	// given a new token, or the sandbox's port URLs blocked).
	CloseStreamRevoked CloseCode = 4403
	// CloseStreamRefused: belt could not open the stream; the reason says
	// why (nothing listening on the port, exec turned off).
	CloseStreamRefused CloseCode = 4502
)

// Int is the code as WebSocket libraries take it.
func (c CloseCode) Int() int { return int(c) }

func (c CloseCode) String() string {
	switch c {
	case CloseStreamRevoked:
		return "stream revoked"
	case CloseStreamRefused:
		return "stream refused"
	}
	return "close code " + strconv.Itoa(int(c))
}
