package strutil

import (
	"regexp"
	"strings"
)

// MaxNameLength caps every resource name that ends up in a URL or a
// namespace/name ref: apps, agents, flows, knowledge, skills, artifacts, MCP
// server slugs, team usernames.
const MaxNameLength = 64

// NameRule is the human-readable form of the name rule for error messages.
const NameRule = "lowercase letters, digits and single hyphens, starting and ending with a letter or digit (e.g. 'my-app')"

// nameRE encodes the rule: lowercase alphanumeric runs joined by single
// hyphens. The grouping rules out leading, trailing and doubled hyphens in
// one scan.
var nameRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// nonName matches every run of characters the name rule disallows.
var nonName = regexp.MustCompile(`[^a-z0-9]+`)

// IsValidName reports whether name satisfies the resource-name rule.
func IsValidName(name string) bool {
	return len(name) <= MaxNameLength && nameRE.MatchString(name)
}

// NormalizeName turns a human-typed title or a foreign identifier into a name
// that passes IsValidName, or "" when nothing usable remains. Use it only
// where the caller did not choose an address (a slug derived from a title, an
// imported skill name, an error-message suggestion); never rewrite a name the
// caller typed, or they end up publishing at an address they did not pick.
func NormalizeName(s string) string {
	// Slugify lowercases and transliterates unicode but keeps underscores and
	// other bytes the rule rejects, so the charset filter still has to run.
	s = nonName.ReplaceAllString(Slugify(s), "-")
	s = strings.Trim(s, "-")
	if len(s) > MaxNameLength {
		s = s[:MaxNameLength]
		if i := strings.LastIndex(s, "-"); i > 0 {
			s = s[:i]
		}
		s = strings.Trim(s, "-")
	}
	return s
}
