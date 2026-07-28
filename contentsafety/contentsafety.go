// Package contentsafety inspects and sanitizes untrusted content.
//
// It covers two threats that share one rule corpus:
//
//   - secrets leaking outward — credentials that ended up in content we serve;
//   - instructions leaking inward — prompt injection aimed at an agent that
//     reads the content.
//
// Two verbs apply the same rules for different purposes. Detect reports
// findings without modifying anything, for a publish or upload gate where a
// human sees the result. Clean rewrites matches in place, for content served
// straight to an agent where nobody reviews the outcome.
//
// Those verbs have opposite tolerances for a false positive: a noisy Detect
// costs someone a triage, while a noisy Clean silently corrupts a document. So
// every rule declares which verbs it is precise enough for, and Clean only ever
// applies rules marked CleanSafe.
package contentsafety

import (
	"encoding/json"
	"regexp"
	"strings"
)

// RuleSet selects which families of rules to apply. Values are bit flags, so a
// caller composes exactly the coverage it wants.
type RuleSet uint16

const (
	// Credentials matches API keys, tokens, private keys, and connection
	// strings — including belt's own key format.
	Credentials RuleSet = 1 << iota

	// Injection matches attempts to override an agent's instructions.
	Injection

	// SpecialTokens matches chat-template delimiters that could forge a role
	// boundary in a model's context.
	SpecialTokens

	// HiddenContent matches text concealed from human review: zero-width
	// characters, direction overrides, script in non-visible areas.
	HiddenContent

	// Exfiltration matches commands that pipe secrets to a network endpoint.
	Exfiltration

	// Destructive matches destructive shell operations.
	Destructive

	// MeetingSecrets matches passcodes embedded in conference join URLs.
	MeetingSecrets

	// Malicious matches other hostile behaviour in executable content:
	// obfuscated payloads, dependency confusion, reconnaissance, path
	// traversal, and suspicious downloads.
	Malicious

	// AllRules selects every family.
	AllRules = RuleSet(^uint16(0))
)

// Verb records which operations a rule is precise enough to drive.
type Verb uint8

const (
	// DetectOnly rules may report a finding but must never rewrite content.
	// Heuristic phrase matches belong here: redacting the sentence "ignore all
	// previous instructions" out of a document *about* prompt injection would
	// itself be a defect.
	DetectOnly Verb = 1 << iota

	// CleanSafe rules match a structured, unambiguous format and may rewrite
	// content. A literal "<|im_start|>" or a key with a registered prefix
	// qualifies; a bare 32-character hex string does not.
	CleanSafe
)

// Severity levels, ordered clean < warning < critical.
const (
	SeverityCritical = ScanSeverityCritical
	SeverityWarning  = ScanSeverityWarning
	SeverityClean    = ScanSeverityClean
)

// Finding is one rule match.
type Finding = ScanFinding

// Result aggregates findings and the highest severity among them.
type Result = ScanResult

// Detect reports every rule in sets that matches content, without modifying it.
// Both DetectOnly and CleanSafe rules participate.
//
// Content is scanned twice: once as written, and once normalized to defeat
// evasion via confusable characters, zero-width joiners, and spaced-out text.
func Detect(content string, sets RuleSet) Result {
	result := Result{Severity: SeverityClean}
	detectInto(&result, "", content, sets)
	return result
}

// DetectFile is Detect with a path recorded on each finding, for callers
// scanning several files into one result.
func DetectFile(result *Result, path, content string, sets RuleSet) {
	detectInto(result, path, content, sets)
}

func detectInto(result *Result, path, content string, sets RuleSet) {
	if result.Severity == "" {
		result.Severity = SeverityClean
	}
	scanContentRules(result, path, content, func(r *rule) bool {
		return r.Sets&sets != 0
	})
}

// Clean rewrites every CleanSafe match in sets to a placeholder and reports
// what it replaced. DetectOnly rules are skipped: they are not precise enough
// to mutate content nobody will review.
//
// Clean operates on plain text. Never call it on serialized JSON — a pattern
// matching across a string boundary consumes the closing quote and corrupts the
// document. Use CleanJSON, which walks decoded string values individually.
func Clean(content string, sets RuleSet) (string, []Finding) {
	var findings []Finding
	for i := range rules {
		r := &rules[i]
		if r.Sets&sets == 0 || r.Verbs&CleanSafe == 0 {
			continue
		}
		for _, pattern := range r.Patterns {
			content = replaceReporting(content, pattern, r, &findings)
		}
	}
	return content, findings
}

func replaceReporting(content string, pattern *regexp.Regexp, r *rule, findings *[]Finding) string {
	return pattern.ReplaceAllStringFunc(content, func(match string) string {
		*findings = append(*findings, Finding{
			RuleID:      r.ID,
			Severity:    r.Severity,
			Description: r.Description,
			Match:       truncateMatch(match),
		})
		return r.Placeholder
	})
}

// MarshalFindings renders findings as JSON for logging. Returns "" for none.
func MarshalFindings(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}
	data, err := json.Marshal(findings)
	if err != nil {
		return `[{"error":"marshal failed"}]`
	}
	return string(data)
}

// HasCritical reports whether any finding is critical.
func HasCritical(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// Normalize folds confusable characters, strips zero-width codepoints, and
// collapses spaced-out text. Exported so callers can compare a normalized form
// against the original when reporting evasion.
func Normalize(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = normalizeLine(line)
	}
	return strings.Join(lines, "\n")
}
