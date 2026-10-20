// Package secretshape finds values that look like a well-known credential:
// a key a person pasted, a token a server minted and echoed. It is the one
// list the API's scrub chokepoint and the engine's redactor share, so a
// shape added here is caught in both.
//
// The shapes are conservative, prefixes vendors chose to be unmistakable,
// so ordinary text never matches. A JWT is deliberately absent: signed URLs
// and session cookies look like one, and tools legitimately return those.
// No shape may span a quote, so a JSON document stays a JSON document.
package secretshape

import "regexp"

// Placeholder is what Redact puts in place of a match by default.
const Placeholder = "[REDACTED]"

// Shapes are the credential shapes, each a whole value.
var Shapes = []*regexp.Regexp{
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`),                    // OpenAI, Anthropic (sk-ant-); Stripe uses sk_
	regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`), // Stripe
	regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}`), // GitHub
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}`),             // GitHub fine-grained
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`),                 // GitLab
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),             // Slack
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                       // AWS access key id
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),                  // Google API key
	regexp.MustCompile(`\bya29\.[A-Za-z0-9_-]{20,}`),                 // Google OAuth access token
	regexp.MustCompile(`\binfrt-[A-Za-z0-9_-]{16,}`),                 // inference.sh OAuth refresh token
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[^"]*?-----END [A-Z ]*PRIVATE KEY-----`),
}

// Bearer is a dumped Authorization header. The scheme stays, the token goes.
var Bearer = regexp.MustCompile(`(?i)(authorization["']?\s*[:=]\s*["']?(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{16,}`)

// Redact replaces every match in text with placeholder (Placeholder when
// empty) and reports how many it replaced. Text with no match is returned
// as is.
func Redact(text, placeholder string) (string, int) {
	if placeholder == "" {
		placeholder = Placeholder
	}
	n := 0
	for _, re := range Shapes {
		text = re.ReplaceAllStringFunc(text, func(string) string { n++; return placeholder })
	}
	text = Bearer.ReplaceAllStringFunc(text, func(m string) string {
		n++
		return Bearer.ReplaceAllString(m, "${1}"+placeholder)
	})
	return text, n
}
