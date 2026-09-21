// Package relaywire holds the numbers a socket relay and the ends that dial
// it have to agree on. It imports nothing, so an end can share a limit with
// the relay without taking on the relay's dependencies.
package relaywire

// WaitingFrames is how many frames a relay holds for an end whose peer has
// not arrived yet; past it the relay stops reading that end. An end that
// redials after a relay restart may send again at most this many frames
// without blocking, so a worker remembers no more than this.
const WaitingFrames = 64
