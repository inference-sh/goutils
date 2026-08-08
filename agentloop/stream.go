package agentloop

import "context"

// StreamFn calls the LLM and returns the assistant's response.
//
// This is the only LLM integration point. Consumers implement it by calling
// their provider SDK (Anthropic, OpenAI, a local model, or an app engine).
// The function receives the full context and returns a complete assistant
// message with usage stats.
//
// For streaming, the consumer handles token-by-token delivery internally
// (SSE, WebSocket, stdout) — the loop only needs the final message.
type StreamFn func(ctx context.Context, req StreamRequest) (*StreamResponse, error)

// StreamRequest is the input to a StreamFn call — one per turn.
type StreamRequest struct {
	SystemPrompt string
	Messages     []Message
	Tools        []ToolDef

	// Params carries provider-specific settings (temperature, max tokens,
	// model ID, etc). The loop passes it through unchanged — consumers set
	// it via TurnUpdate.Params or the initial loop configuration.
	Params any
}

// StreamResponse is the output of a StreamFn call.
type StreamResponse struct {
	Message Message
	Usage   Usage
}

// ToolExecutor runs a single tool call and returns its result.
// The consumer maps tool names to implementations.
type ToolExecutor func(ctx context.Context, call ToolCall) (ToolResult, error)
