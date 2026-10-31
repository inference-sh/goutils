package escmask

import (
	"regexp"
	"testing"
)

func TestMask(t *testing.T) {
	cases := map[string]string{
		`plain`:         `plain`,
		`a\nb`:          `a\ b`,
		`a\tb\rc\bd\fe`: `a\ b\ c\ d\ e`,
		"a\\u0022b":     "a\\     b",
		`a\\nb`:         `a\\nb`, // an escaped backslash, then the letter n
		`a\\\nb`:        `a\\\ b`,
		`a\"b`:          `a\"b`,
		`a\u12`:         `a\u12`, // not a \u escape
		`trailing\`:     `trailing\`,
	}
	for in, want := range cases {
		got := Mask(in)
		if got != want || len(got) != len(in) {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReplaceAll_afterEscape(t *testing.T) {
	re := regexp.MustCompile(`\binfrt-[a-z]{4}`)
	in := `{"text":"line\ninfrt-abcd and` + "\\u0020" + `infrt-efgh, not xinfrt-ijkl"}`
	got := ReplaceAll(re, in, func(string, []int) string { return "[R]" })
	want := `{"text":"line\n[R] and` + "\\u0020" + `[R], not xinfrt-ijkl"}`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}
