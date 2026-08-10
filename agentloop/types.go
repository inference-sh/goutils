// Package agentloop provides a provider-agnostic agent loop with pluggable
// hooks for tool dispatch, context management, and compaction.
//
// The loop operates on [Message] values — a role plus content blocks — and
// delegates LLM calls and tool execution to caller-supplied functions. This
// keeps the package free of provider SDKs, databases, and HTTP frameworks so
// the same loop can drive a server-side agent runtime or a local CLI agent.
package agentloop

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Message roles
// ---------------------------------------------------------------------------

type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// IsLLMRole returns true for roles the LLM provider understands on the wire.
func (r Role) IsLLMRole() bool {
	return r == RoleSystem || r == RoleUser || r == RoleAssistant || r == RoleTool
}

// ---------------------------------------------------------------------------
// Content blocks
// ---------------------------------------------------------------------------

type ContentType string

const (
	ContentText      ContentType = "text"
	ContentReasoning ContentType = "reasoning"
	ContentImage     ContentType = "image"
	ContentFile      ContentType = "file"
	ContentToolCalls ContentType = "tool_calls"
	ContentToolResult ContentType = "tool_result"
)

type Content struct {
	Type       ContentType `json:"type"`
	Text       string      `json:"text,omitempty"`
	ToolCalls  []ToolCall  `json:"tool_calls,omitempty"`
	ToolCallID string      `json:"tool_call_id,omitempty"`
	IsError    bool        `json:"is_error,omitempty"`
	Images     []string    `json:"images,omitempty"`
	Files      []string    `json:"files,omitempty"`
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

// Message is the loop's unit of conversation history.
// Provider-agnostic — the ConvertToLLM hook adapts these to wire format.
type Message struct {
	Role    Role      `json:"role"`
	Content []Content `json:"content"`

	// Metadata is extensible storage for consumer-specific data (TTL, dedup
	// keys, compaction markers, injection source). The loop never reads it;
	// hooks and consumers use it freely.
	Meta map[string]any `json:"meta,omitempty"`
}

// Text returns the concatenated text content of the message.
func (m Message) Text() string {
	var b strings.Builder
	for _, c := range m.Content {
		if c.Type == ContentText {
			b.WriteString(c.Text)
		}
	}
	return b.String()
}

// ToolCalls returns all tool calls from the message's content blocks.
func (m Message) ToolCalls() []ToolCall {
	var calls []ToolCall
	for _, c := range m.Content {
		if c.Type == ContentToolCalls {
			calls = append(calls, c.ToolCalls...)
		}
	}
	return calls
}

// TextMessage is a convenience constructor.
func TextMessage(role Role, text string) Message {
	return Message{
		Role: role,
		Content: []Content{{Type: ContentText, Text: text}},
	}
}

// ToolResultMessage is a convenience constructor for a tool result.
func ToolResultMessage(toolCallID string, text string, isError bool) Message {
	return Message{
		Role: RoleTool,
		Content: []Content{{
			Type:       ContentToolResult,
			Text:       text,
			ToolCallID: toolCallID,
			IsError:    isError,
		}},
	}
}

// ---------------------------------------------------------------------------
// Tool definitions and calls
// ---------------------------------------------------------------------------

type ToolCall struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type ToolResult struct {
	Content string `json:"content"`
	IsError bool   `json:"is_error,omitempty"`

	// AddTools makes new tools available from the next turn onward.
	// The loop merges these into the active tool set.
	AddTools []ToolDef `json:"add_tools,omitempty"`

	// RemoveTools removes tools by name from the next turn onward.
	RemoveTools []string `json:"remove_tools,omitempty"`
}

// ToolDef describes a tool the LLM can call.
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// ---------------------------------------------------------------------------
// Usage / token tracking
// ---------------------------------------------------------------------------

type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// EstimateTokens returns a rough token count using the chars/4 heuristic.
func EstimateTokens(text string) int {
	return len(text) / 4
}

// EstimateMessageTokens estimates the token count for a message.
func EstimateMessageTokens(m Message) int {
	tokens := 4 // per-message overhead
	for _, c := range m.Content {
		tokens += EstimateTokens(c.Text)
		for _, tc := range c.ToolCalls {
			tokens += EstimateTokens(tc.Name) + estimateMapTokens(tc.Arguments)
		}
	}
	return tokens
}

func estimateMapTokens(m map[string]any) int {
	n := 0
	for k, v := range m {
		n += len(k) + len(fmt.Sprint(v))
	}
	return n / 4
}

// EstimateContextTokens returns the estimated total tokens for a message list.
func EstimateContextTokens(messages []Message) int {
	total := 0
	for _, m := range messages {
		total += EstimateMessageTokens(m)
	}
	return total
}
