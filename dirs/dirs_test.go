package dirs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetUserHomeDir(t *testing.T) {
	home := GetUserHomeDir()
	if home == "" {
		t.Error("GetUserHomeDir() returned empty string")
	}
}

func TestExpandTilde(t *testing.T) {
	home := GetUserHomeDir()
	if home == "" {
		t.Skip("cannot get home dir")
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"no tilde", "/some/path", "/some/path"},
		{"tilde only", "~", home},
		{"tilde with path", "~/foo/bar", filepath.Join(home, "foo/bar")},
		{"tilde in middle", "/foo/~/bar", "/foo/~/bar"},
		{"tilde user syntax", "~user/foo", "~user/foo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExpandTilde(tt.input)
			if got != tt.expected {
				t.Errorf("ExpandTilde(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExpandTilde_NoHome(t *testing.T) {
	// Save and clear HOME
	origHome := os.Getenv("HOME")
	os.Unsetenv("HOME")
	defer os.Setenv("HOME", origHome)

	// Even without $HOME, user.Current() should still work
	result := ExpandTilde("~/.cache")
	if result == "~/.cache" {
		// If it couldn't expand, that's okay in some environments
		t.Log("ExpandTilde could not expand without $HOME (user.Current may have failed)")
	} else if result == "" {
		t.Error("ExpandTilde returned empty string")
	}
}
