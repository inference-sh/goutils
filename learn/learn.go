// Package learn holds the knowledge-extraction loop shared by the belt CLI
// hooks and the platform agent runtime: the prompts that pull reusable
// knowledge out of a conversation and decide whether a candidate duplicates an
// existing entry, the structured-output schemas they answer in, the parsers
// for those answers, and when a review should run. Both callers run the same
// tested prompts; each brings its own model call and its own store.
package learn

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed prompts/extract.md
var extractPrompt string

//go:embed prompts/dedup.md
var dedupPrompt string

// ReviewEvery is how many user turns pass between reviews run at the end of a
// turn. Reviews before compaction and at session end run regardless.
const ReviewEvery = 10

// ShouldReview reports whether a review at the end of a turn is due.
func ShouldReview(userTurns int) bool {
	return userTurns > 0 && userTurns%ReviewEvery == 0
}

// Candidate is one piece of knowledge the extraction prompt proposes saving.
type Candidate struct {
	Type    string `json:"type" jsonschema:"required,enum=rule,enum=preference,enum=gotcha,enum=pattern,enum=reference,description=entry type"`
	Name    string `json:"name" jsonschema:"required,description=short slug name; 3-5 words; lowercase-hyphenated,maxLength=64"`
	Content string `json:"content" jsonschema:"required,description=3-8 sentences: WHAT + WHY + HOW TO APPLY"`
	Trigger string `json:"trigger" jsonschema:"required,description=one sentence: WHEN is this relevant?"`
}

// Existing is an entry already in the store that a candidate may duplicate.
type Existing struct {
	Ref         string // namespace/name
	Description string
}

// Dedup actions.
const (
	DedupCreate = "create"
	DedupUpdate = "update"
	DedupSkip   = "skip"
)

// DedupAction is the decision for one candidate against existing entries.
type DedupAction struct {
	Action  string `json:"action" jsonschema:"required,enum=create,enum=update,enum=skip"`
	Target  string `json:"target,omitempty"`
	Content string `json:"content,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// ExtractTemplate is the default extraction prompt. It ends in an open
// <conversation> tag that ExtractPromptWith closes around the transcript.
// Callers that let users override prompts start from it.
func ExtractTemplate() string { return extractPrompt }

// DedupTemplate is the default dedup prompt, with {{name}}, {{type}},
// {{content}} and {{existing}} placeholders.
func DedupTemplate() string { return dedupPrompt }

// ExtractPrompt asks for the reusable knowledge in a conversation transcript
// with the default template. context, when set, goes first (workspace, repo,
// agent).
func ExtractPrompt(context, conversation string) string {
	return ExtractPromptWith(extractPrompt, context, conversation)
}

// ExtractPromptWith is ExtractPrompt with a caller's template.
func ExtractPromptWith(template, context, conversation string) string {
	prompt := template + "\n" + conversation + "\n</conversation>"
	if context != "" {
		prompt = context + "\n\n" + prompt
	}
	return prompt
}

// DedupPrompt asks whether a candidate is new, improves an existing entry or
// is already covered, with the default template.
func DedupPrompt(c Candidate, existing []Existing) string {
	return DedupPromptWith(dedupPrompt, c, existing)
}

// DedupPromptWith is DedupPrompt with a caller's template.
func DedupPromptWith(template string, c Candidate, existing []Existing) string {
	var b strings.Builder
	for _, e := range existing {
		fmt.Fprintf(&b, "- %s: %s\n", e.Ref, e.Description)
	}
	return strings.NewReplacer(
		"{{name}}", c.Name,
		"{{type}}", c.Type,
		"{{content}}", c.Content,
		"{{existing}}", b.String(),
	).Replace(template)
}

// DedupQuery is the search text that finds entries a candidate may duplicate.
func DedupQuery(c Candidate) string {
	q := c.Name + " " + c.Content
	if len(q) > 200 {
		q = q[:200]
	}
	return q
}

// ParseCandidates reads an extraction answer ({"items": [...]}) and keeps the
// candidates that have both a name and content.
func ParseCandidates(raw []byte) []Candidate {
	var wrapper struct {
		Items []Candidate `json:"items"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil
	}
	var valid []Candidate
	for _, c := range wrapper.Items {
		if c.Name != "" && c.Content != "" {
			valid = append(valid, c)
		}
	}
	return valid
}

// ParseDedup reads a dedup answer. Anything unreadable or without an action
// is a create: a duplicate costs less than a lost insight.
func ParseDedup(raw []byte) DedupAction {
	var a DedupAction
	if err := json.Unmarshal(raw, &a); err != nil || a.Action == "" {
		return DedupAction{Action: DedupCreate}
	}
	return a
}

// CandidatesSchema is the JSON schema an extraction answer conforms to.
func CandidatesSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []any{"items"},
		"properties": map[string]any{
			"items": map[string]any{"type": "array", "items": candidateSchema()},
		},
	}
}

func candidateSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []any{"type", "name", "content", "trigger"},
		"properties": map[string]any{
			"type":    map[string]any{"type": "string", "enum": []any{"rule", "preference", "gotcha", "pattern", "reference"}, "description": "entry type"},
			"name":    map[string]any{"type": "string", "maxLength": 64, "description": "short slug name; 3-5 words; lowercase-hyphenated"},
			"content": map[string]any{"type": "string", "description": "3-8 sentences: WHAT + WHY + HOW TO APPLY"},
			"trigger": map[string]any{"type": "string", "description": "one sentence: WHEN is this relevant?"},
		},
	}
}

// DedupSchema is the JSON schema a dedup answer conforms to.
func DedupSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []any{"action"},
		"properties": map[string]any{
			"action":  map[string]any{"type": "string", "enum": []any{DedupCreate, DedupUpdate, DedupSkip}},
			"target":  map[string]any{"type": "string"},
			"content": map[string]any{"type": "string"},
			"reason":  map[string]any{"type": "string"},
		},
	}
}
