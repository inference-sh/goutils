// Package escmask lets a pattern that starts with \b find a value right after
// a backslash escape. In serialized JSON or NDJSON a value after a newline is
// written "\ninfrt-…": the escape's letter is a word character, so \b sees no
// boundary before the value and the pattern misses it.
//
// Mask returns a copy of the text, the same length, with each escape's letter
// (and a \u escape's hex digits) replaced by a space. Patterns run over the
// mask and their spans are applied to the original, so nothing outside a match
// changes and a match never includes the escape.
package escmask

import (
	"regexp"
	"strings"
)

// Mask returns s with the letters of every \b \f \n \r \t escape and the u and
// four hex digits of every \uXXXX escape replaced by spaces. A backslash that
// is itself escaped (\\n) starts no escape. The result has the length of s.
func Mask(s string) string {
	i := strings.IndexByte(s, '\\')
	if i < 0 {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		if i+1 >= len(b) {
			break
		}
		switch c := b[i+1]; c {
		case 'b', 'f', 'n', 'r', 't':
			b[i+1] = ' '
		case 'u':
			if i+5 < len(b) && isHex4(b[i+2:i+6]) {
				for j := i + 1; j <= i+5; j++ {
					b[j] = ' '
				}
				i += 5
				continue
			}
		}
		i++ // the escaped character is consumed, so \\ never starts a second escape
	}
	return string(b)
}

func isHex4(b []byte) bool {
	for _, c := range b {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

// ReplaceAll replaces every match of re in s, found on Mask(s), with
// repl(s, loc), where loc are the submatch indexes into s as from
// FindAllStringSubmatchIndex.
func ReplaceAll(re *regexp.Regexp, s string, repl func(s string, loc []int) string) string {
	locs := re.FindAllStringSubmatchIndex(Mask(s), -1)
	if len(locs) == 0 {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	last := 0
	for _, loc := range locs {
		out.WriteString(s[last:loc[0]])
		out.WriteString(repl(s, loc))
		last = loc[1]
	}
	out.WriteString(s[last:])
	return out.String()
}

// FindIndex is re.FindStringIndex over Mask(s).
func FindIndex(re *regexp.Regexp, s string) []int {
	return re.FindStringIndex(Mask(s))
}
