package agentloop

import "context"

// Hooks contains optional callbacks for every interception point in the loop.
// A nil field means "use the default behavior." Consumers wire platform-specific
// logic (persistence, auth, UI updates) through these hooks without the loop
// importing any platform packages.
type Hooks struct {
	// TransformContext processes the raw message history before it is sent to
	// ConvertToLLM. Use this for compaction boundary enforcement, injection
	// filtering, TTL expiry, or rewriting internal message roles.
	TransformContext func(ctx context.Context, messages []Message) ([]Message, error)

	// ConvertToLLM adapts []Message to the provider's wire format. The loop
	// calls this immediately before StreamFn. If nil, the loop passes messages
	// through unchanged (only forwarding messages with IsLLMRole() == true).
	ConvertToLLM func(ctx context.Context, messages []Message) ([]Message, error)

	// PrepareNextTurn is called between turns — after tool results are
	// collected and before the next LLM call. Return a non-nil TurnUpdate to
	// swap tools, system prompt, or the stream function for the next turn.
	// Return nil to keep everything as-is.
	PrepareNextTurn func(ctx context.Context, tc TurnContext) (*TurnUpdate, error)

	// ShouldStop is called after each assistant response. Return true to end
	// the loop. If nil, the loop stops when the assistant produces no tool
	// calls (the natural completion signal).
	ShouldStop func(ctx context.Context, sc StopContext) bool

	// BeforeToolCall is called before each tool execution. Return a non-nil
	// BeforeToolCallResult to block the call or hint termination.
	// Return nil to proceed normally.
	BeforeToolCall func(ctx context.Context, tc BeforeToolCallContext) (*BeforeToolCallResult, error)

	// AfterToolCall is called after each tool execution with the result.
	// Return a non-nil AfterToolCallResult to modify the result content, flip
	// the error flag, or hint termination.
	AfterToolCall func(ctx context.Context, tc AfterToolCallContext) (*AfterToolCallResult, error)

	// OnEvent receives lifecycle events for logging, persistence, metrics, or
	// webhook dispatch. The loop never blocks on this — errors are the
	// consumer's concern.
	OnEvent func(ctx context.Context, event Event)
}

// ---------------------------------------------------------------------------
// Hook context types
// ---------------------------------------------------------------------------

// TurnContext is passed to PrepareNextTurn.
type TurnContext struct {
	TurnNumber    int
	Messages      []Message
	LastAssistant *Message
	Tools         []ToolDef
	SystemPrompt  string
}

// TurnUpdate is returned from PrepareNextTurn to change loop state.
type TurnUpdate struct {
	Tools        []ToolDef // nil = keep current
	SystemPrompt *string   // nil = keep current
	StreamFn     StreamFn  // nil = keep current
	Params       any       // nil = keep current; provider-specific settings
}

// StopContext is passed to ShouldStop.
type StopContext struct {
	TurnNumber    int
	Messages      []Message
	LastAssistant Message
	ToolCalls     []ToolCall
	ToolResults   []ToolResult
}

// BeforeToolCallContext is passed to BeforeToolCall.
type BeforeToolCallContext struct {
	TurnNumber int
	Call       ToolCall
	Assistant  Message
	Messages   []Message
}

// BeforeToolCallResult controls whether a tool call proceeds.
type BeforeToolCallResult struct {
	// Block prevents the tool from executing. The loop injects an error
	// tool result with Reason as the message.
	Block  bool
	Reason string

	// Terminate hints that the loop should stop after the current tool batch.
	// Only takes effect when every tool call in the batch sets this.
	Terminate bool
}

// AfterToolCallContext is passed to AfterToolCall.
type AfterToolCallContext struct {
	TurnNumber int
	Call       ToolCall
	Result     ToolResult
	Assistant  Message
	Messages   []Message
}

// AfterToolCallResult can modify the tool result before it enters history.
type AfterToolCallResult struct {
	Content   *string // nil = keep original
	IsError   *bool   // nil = keep original
	Terminate bool
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

type EventType string

const (
	EventLoopStart    EventType = "loop.start"
	EventTurnStart    EventType = "turn.start"
	EventTurnEnd      EventType = "turn.end"
	EventToolCall     EventType = "tool.call"
	EventToolResult   EventType = "tool.result"
	EventLoopEnd      EventType = "loop.end"
	EventLoopError    EventType = "loop.error"
	EventCompaction   EventType = "compaction"
	EventSteerInject  EventType = "steer.inject"
)

// Event carries lifecycle data from the loop to observers.
type Event struct {
	Type       EventType
	TurnNumber int
	Data       any // typed per EventType — ToolCall, ToolResult, error, etc.
}
