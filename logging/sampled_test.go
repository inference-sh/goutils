package logging

import (
	"testing"
	"time"
)

func TestSampled_FirstCallAllowed(t *testing.T) {
	s := NewSampled(time.Minute)
	if !s.Should("key") {
		t.Fatal("first call should be allowed")
	}
}

func TestSampled_SecondCallSuppressed(t *testing.T) {
	s := NewSampled(time.Minute)
	s.Should("key")
	if s.Should("key") {
		t.Fatal("second call within interval should be suppressed")
	}
}

func TestSampled_DifferentKeysIndependent(t *testing.T) {
	s := NewSampled(time.Minute)
	s.Should("a")
	if !s.Should("b") {
		t.Fatal("different key should be independent")
	}
}

func TestSampled_ExpiredIntervalAllowed(t *testing.T) {
	s := NewSampled(time.Millisecond)
	s.Should("key")
	time.Sleep(2 * time.Millisecond)
	if !s.Should("key") {
		t.Fatal("should allow after interval expires")
	}
}
