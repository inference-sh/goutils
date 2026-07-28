package contentsafety

import "strings"

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

// KeyClass describes how a JSON string value should be treated.
type KeyClass int

const (
	// ClassContent is prose a model may read. Eligible for cleaning and
	// untrusted marking.
	ClassContent KeyClass = iota
	// ClassMetadata is an identifier or machine value. Left untouched so
	// programs consuming the output keep working.
	ClassMetadata
)

// ClassifyKey reports how the value at key, reached through path, should be
// treated. An empty key means an array element or a root scalar, which inherits
// its enclosing context.
func ClassifyKey(path []string, key string) KeyClass {
	k := normalizeKey(key)

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
