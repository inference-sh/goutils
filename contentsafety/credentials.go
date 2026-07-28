package contentsafety

// Placeholders written in place of a match.
const (
	redactedCredential = "[REDACTED]"
	removedToken       = "[REMOVED_SPECIAL_TOKEN]"
)

// credentialRules match structured secret formats. Unlike the behavioural
// rules they are precise enough to rewrite content, so they carry CleanSafe.
//
// The bar for admission here is a distinctive prefix or a fixed shape that
// cannot plausibly occur in prose. A bare 32-character hex string does not
// qualify, however often it is a real key: redacting it would corrupt
// checksums, commit hashes, and UUIDs in ordinary documents.
var credentialRules = []rule{
	{
		ID:          "INF-CRED-001",
		Severity:    SeverityCritical,
		Description: "inference.sh API key",
		Sets:        Credentials,
		Verbs:       DetectOnly | CleanSafe,
		Placeholder: redactedCredential,
		// "1nfsh-" + a lowercased ULID (Crockford base32, no i/l/o/u).
		Patterns: compilePatterns(`\b1nfsh-[0-9a-hjkmnp-tv-z]{26}\b`),
	},
	{
		ID:          "INF-CRED-002",
		Severity:    SeverityCritical,
		Description: "inference.sh session or invite token",
		Sets:        Credentials,
		// Detect-only by design. Invite tokens are two concatenated lowercased
		// ULIDs with no distinctive prefix, so the pattern is just "52 base32
		// characters" — the same shape as a hash or a long identifier. That
		// fails the admission bar above, so it is reported for a human but
		// never rewritten.
		Verbs:    DetectOnly,
		Patterns: compilePatterns(`\b[0-9a-hjkmnp-tv-z]{52}\b`),
	},
	{
		ID:          "INF-CRED-003",
		Severity:    SeverityCritical,
		Description: "Third-party provider credential",
		Sets:        Credentials,
		Verbs:       DetectOnly | CleanSafe,
		Placeholder: redactedCredential,
		Patterns:    redactionPatterns,
	},
	{
		ID:          "INF-CRED-004",
		Severity:    SeverityWarning,
		Description: "Conference join URL with embedded passcode",
		Sets:        MeetingSecrets,
		Verbs:       DetectOnly | CleanSafe,
		Placeholder: redactedCredential,
		Patterns: compilePatterns(
			`(?i)(?:\?|&)pwd=[A-Za-z0-9._-]+`,
			`(?i)(?:\?|&)passcode=[A-Za-z0-9._-]+`,
		),
	},
}

// specialTokenRules match chat-template delimiters. Left intact in content that
// reaches a model, they can terminate the current message and open a new one
// with a forged role, which is why they are rewritten rather than only
// reported.
var specialTokenRules = []rule{
	{
		ID:          "INF-TOK-001",
		Severity:    SeverityCritical,
		Description: "Chat template delimiter — could forge a role boundary in a model's context",
		Sets:        SpecialTokens,
		Verbs:       DetectOnly | CleanSafe,
		Placeholder: removedToken,
		Patterns: compilePatterns(
			`<\|im_start\|>`, `<\|im_end\|>`,
			`<\|endoftext\|>`, `<\|begin_of_text\|>`, `<\|end_of_text\|>`,
			`<\|start_header_id\|>`, `<\|end_header_id\|>`,
			`<\|eot_id\|>`, `<\|eom_id\|>`, `<\|python_tag\|>`,
			`<\|channel\|>`, `<\|message\|>`, `<\|return\|>`, `<\|call\|>`,
			`<\|reserved_special_token_\d+\|>`,
			`\[/?INST\]`, `<</?SYS>>`,
			`<start_of_turn>`, `<end_of_turn>`,
		),
	},
}

func init() {
	// Registered after the behavioural corpus so Detect reports them in a
	// stable order.
	rules = append(rules, credentialRules...)
	rules = append(rules, specialTokenRules...)
}
