package contentsafety

import (
	"regexp"
	"strings"
)

// Key classification decides, per JSON field, whether a string is content an
// agent will read or metadata a program depends on.
//
// It matters in both directions. Rewriting or wrapping an id, uri, or cursor
// breaks callers that parse the output. Leaving a body, description, or tool
// result unmarked hands third-party text to a model with nothing separating it
// from the operator's own instructions.
//
// Unknown keys are treated as content. An unrecognized field is more likely to
// be a description than an identifier, and the cost of being wrong is
// asymmetric: over-marking is visible and annoying, under-marking is silent.
// The metadata list is therefore the one that must be complete.

// metadataKeys are fields whose values are identifiers, locators, or machine
// state. Derived from belt's DTOs in github.com/inference-sh/models.
var metadataKeys = map[string]bool{
	// identity
	"id": true, "short_id": true, "slug": true, "namespace": true,
	"version": true, "version_id": true, "app_id": true, "app_version_id": true,
	"agent_id": true, "agent_version_id": true, "task_id": true, "chat_id": true,
	"chat_message_id": true, "team_id": true, "user_id": true, "worker_id": true,
	"flow_id": true, "flow_run_id": true, "session_id": true, "node_id": true,
	"parent_id": true, "client_id": true, "request_id": true, "trace_id": true,

	// locators
	"uri": true, "url": true, "api_url": true, "auth_url": true,
	"approve_url": true, "cancel_url": true, "docs_url": true, "avatar_url": true,
	"webhook_url": true, "path": true, "file_path": true, "endpoint": true,

	// integrity and pagination
	"hash": true, "content_hash": true, "commit_hash": true, "etag": true,
	"sha": true, "digest": true, "checksum": true,
	"cursor": true, "next_cursor": true, "page": true, "page_token": true,
	"next_page_token": true,

	// timestamps
	"created_at": true, "updated_at": true, "deleted_at": true,
	"completed_at": true, "started_at": true, "expires_at": true,
	"authorized_at": true, "delivered_at": true, "timestamp": true,

	// enums and machine state
	"status": true, "state": true, "type": true, "kind": true, "role": true,
	"mime_type": true, "content_type": true, "format": true, "encoding": true,
	"size": true, "count": true, "call_count": true, "index": true,
	"visibility": true, "provider": true, "region": true, "country_code": true,

	// schemas are structure, not prose
	"input_schema": true, "output_schema": true, "schema": true,
}

// contentKeys are fields that carry human or model-facing prose. Listed
// explicitly so the intent is reviewable, though an unknown key is treated as
// content anyway.
var contentKeys = map[string]bool{
	"content": true, "instructions": true, "description": true, "text": true,
	"body": true, "message": true, "summary": true, "title": true,
	"prompt": true, "answer": true, "question": true, "note": true,
	"notes": true, "comment": true, "output": true, "result": true,
	"error": true, "reason": true, "label": true, "name": true,
	"display_name": true, "value": true, "snippet": true, "excerpt": true,
	"readme": true, "changelog": true, "response": true,
}

// containerKeys are array or object fields whose descendants are content
// regardless of their own key, such as a list of messages or tool results.
var containerKeys = map[string]bool{
	"messages": true, "results": true, "items": true, "choices": true,
	"outputs": true, "files": true, "logs": true, "events": true,
	"findings": true, "suggestions": true, "tools": true, "content": true,
}

// secretKeys are fields whose value is credential material because of what the
// field is, not what the value looks like. Pattern matching cannot reach these:
// a masked secret, a random passphrase or an opaque OAuth token resembles no
// vendor format, so a value-only scrubber passes it through untouched.
//
// Only unambiguous names belong here. "key" and "value" are deliberately absent
// — both are ordinary field names across belt's payloads ("key" is a secret's
// *name*, "value" appears throughout flow graphs), and redacting them would
// destroy useful data to protect something that is not there.
var secretKeys = map[string]bool{
	"secret": true, "secrets": true, "client_secret": true,
	"password": true, "passwd": true, "pwd": true, "passcode": true,
	"token": true, "access_token": true, "refresh_token": true,
	"id_token": true, "session_token": true, "bearer": true,
	"api_key": true, "private_key": true, "secret_key": true,
	"credential": true, "credentials": true, "authorization": true,
	"cookie": true, "set_cookie": true,
	// A masked value still exposes its last four characters, which is enough to
	// be worth withholding when the payload is written to a committed fixture.
	"masked_value": true,
}

// KeyClass describes how a JSON string value should be treated.
type KeyClass int

const (
	// ClassContent is prose a model may read. Eligible for cleaning and
	// untrusted marking.
	ClassContent KeyClass = iota
	// ClassMetadata is an identifier or machine value. Left untouched so
	// programs consuming the output keep working.
	ClassMetadata
	// ClassSecret is credential material identified by its field name. Always
	// redacted, whatever the value looks like.
	ClassSecret
)

// ClassifyKey reports how the value at key, reached through path, should be
// treated. An empty key means an array element or a root scalar, which inherits
// its enclosing context.
func ClassifyKey(path []string, key string) KeyClass {
	k := normalizeKey(key)

	// Checked first: a field named for a secret is a secret even when another
	// table also claims the name.
	if secretKeys[k] {
		return ClassSecret
	}
	if metadataKeys[k] {
		return ClassMetadata
	}
	if contentKeys[k] {
		return ClassContent
	}
	// Anything inside a known content container is content, whatever it is
	// called — this is how a tool result's arbitrary fields get marked.
	for _, part := range path {
		if containerKeys[normalizeKey(part)] {
			return ClassContent
		}
	}
	// Unknown key: treat as content. See the package note on asymmetry.
	return ClassContent
}

// normalizeKey folds the spellings the same field arrives under across belt's
// JSON, Go, and third-party MCP payloads: created_at, createdAt, CreatedAt.
func normalizeKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'A' && c <= 'Z':
			// camelCase boundary becomes an underscore, so createdAt and
			// created_at normalize alike.
			if i > 0 && key[i-1] >= 'a' && key[i-1] <= 'z' {
				b.WriteByte('_')
			}
			b.WriteByte(c + ('a' - 'A'))
		case c == '-':
			b.WriteByte('_')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// jsonFieldRe matches a JSON string field and captures its name, the separator,
// and the value. Bounded name and value character sets keep it linear and stop a
// match from spanning two fields.
var jsonFieldRe = regexp.MustCompile(`"([A-Za-z0-9_.\-]{1,64})"(\s*:\s*)"((?:[^"\\]|\\.)*)"`)

// RedactSecretFields replaces the value of every JSON field whose name denotes
// secret material, without decoding the document.
//
// It exists for callers that cannot re-encode. Recorded HTTP chunks are
// arbitrary byte fragments whose boundaries are the thing being reproduced, so
// decoding and re-serializing them would rewrite whitespace and move a boundary;
// a text substitution changes only the matched span. CleanJSON is the better
// choice whenever re-encoding is acceptable.
//
// The field name is classified rather than matched against a list of spellings,
// so maskedValue, masked_value and masked-value are all covered.
//
// Same limitation as the value patterns: a field split across two fragments is
// not matched.
func RedactSecretFields(s string) (string, []Finding) {
	matches := jsonFieldRe.FindAllStringSubmatchIndex(s, -1)
	if matches == nil {
		return s, nil
	}

	var b strings.Builder
	var findings []Finding
	last := 0
	for _, m := range matches {
		name := s[m[2]:m[3]]
		if ClassifyKey(nil, name) != ClassSecret || m[7] == m[6] {
			continue // not secret, or already empty
		}
		b.WriteString(s[last:m[6]])
		b.WriteString(redactedCredential)
		last = m[7]
		findings = append(findings, Finding{
			RuleID:   "INF-CRED-005",
			Severity: SeverityCritical,
			Match:    name,
		})
	}
	if findings == nil {
		return s, nil
	}
	b.WriteString(s[last:])
	return b.String(), findings
}
