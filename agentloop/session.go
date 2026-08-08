package agentloop

import (
	"context"
	"fmt"
	"sync"
)

// Session manages conversation state, hooks, and context logic without
// owning execution. Callers drive the state machine by calling its methods
// in sequence — either synchronously (CLI) or from async event handlers
// (server).
//
// The Session is the shared brain; the execution model is the caller's
// business.
type Session struct {
	mu           sync.Mutex
	hooks        Hooks
	systemPrompt string
	tools        []ToolDef
	params       any
	maxTurns     int
	compaction   *CompactionConfig
	messages     []Message
	turn         int
	steering     *messageQueue
	followUp     *messageQueue

	// Per-turn state for tracking tool results
	pendingCalls  []ToolCall
	pendingResult []ToolResult
	resultCount   int
}

// SessionOption configures a Session.
type SessionOption func(*Session)

func WithSessionHooks(h Hooks) SessionOption           { return func(s *Session) { s.hooks = h } }
func WithSessionSystemPrompt(p string) SessionOption   { return func(s *Session) { s.systemPrompt = p } }
func WithSessionTools(t []ToolDef) SessionOption       { return func(s *Session) { s.tools = t } }
func WithSessionParams(p any) SessionOption            { return func(s *Session) { s.params = p } }
func WithSessionMaxTurns(n int) SessionOption          { return func(s *Session) { s.maxTurns = n } }
func WithSessionCompaction(c CompactionConfig) SessionOption {
	return func(s *Session) { s.compaction = &c }
}

// NewSession creates a Session with the given initial messages and options.
func NewSession(messages []Message, opts ...SessionOption) *Session {
	s := &Session{
		maxTurns: 100,
		messages: messages,
		steering: newMessageQueue(QueueAll),
		followUp: newMessageQueue(QueueAll),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Steer injects a message between turns. Thread-safe.
func (s *Session) Steer(msg Message) {
	s.steering.Enqueue(msg)
}

// FollowUp queues a message for after the session would otherwise stop.
func (s *Session) FollowUp(msg Message) {
	s.followUp.Enqueue(msg)
}

// Messages returns the current conversation history.
func (s *Session) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.messages
}

// Turn returns the current turn number.
func (s *Session) Turn() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.turn
}

// SetMessages replaces the conversation history. Use when reloading
// state from a persistent store between async event boundaries.
func (s *Session) SetMessages(msgs []Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = msgs
}

// NextRequest prepares the LLM call for the current turn. It drains
// steering messages, runs compaction, applies TransformContext and
// ConvertToLLM hooks, and returns the ready-to-send request.
//
// Returns nil if the session has exceeded maxTurns.
func (s *Session) NextRequest(ctx context.Context) (*StreamRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.turn >= s.maxTurns {
		s.emit(ctx, Event{Type: EventLoopEnd, TurnNumber: s.turn, Data: "max_turns"})
		return nil, nil
	}

	// Drain steering
	for _, msg := range s.steering.Drain() {
		s.messages = append(s.messages, msg)
		s.emit(ctx, Event{Type: EventSteerInject, TurnNumber: s.turn, Data: msg})
	}

	// Auto-compact
	if s.compaction != nil {
		compacted, cr, err := AutoCompact(ctx, s.messages, *s.compaction)
		if err != nil {
			s.emit(ctx, Event{Type: EventLoopError, TurnNumber: s.turn, Data: err})
		} else if cr != nil {
			s.messages = compacted
			s.emit(ctx, Event{Type: EventCompaction, TurnNumber: s.turn, Data: cr})
		}
	}

	s.emit(ctx, Event{Type: EventTurnStart, TurnNumber: s.turn})

	// Transform context
	llmMessages := s.messages
	if s.hooks.TransformContext != nil {
		var err error
		llmMessages, err = s.hooks.TransformContext(ctx, s.messages)
		if err != nil {
			return nil, fmt.Errorf("transform context: %w", err)
		}
	}

	// Convert to LLM wire format
	if s.hooks.ConvertToLLM != nil {
		var err error
		llmMessages, err = s.hooks.ConvertToLLM(ctx, llmMessages)
		if err != nil {
			return nil, fmt.Errorf("convert to llm: %w", err)
		}
	} else {
		llmMessages = defaultConvertToLLM(llmMessages)
	}

	return &StreamRequest{
		SystemPrompt: s.systemPrompt,
		Messages:     llmMessages,
		Tools:        s.tools,
		Params:       s.params,
	}, nil
}

// HandleResponse processes an LLM response. Appends the assistant message
// to history and returns tool calls to execute. Empty slice means the
// assistant produced no tool calls (natural stop).
func (s *Session) HandleResponse(ctx context.Context, resp StreamResponse) []ToolCall {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.messages = append(s.messages, resp.Message)
	calls := resp.Message.ToolCalls()

	if len(calls) == 0 {
		s.emit(ctx, Event{Type: EventTurnEnd, TurnNumber: s.turn, Data: resp.Usage})
		s.pendingCalls = nil
		s.pendingResult = nil
		s.resultCount = 0
		return nil
	}

	// Set up tracking for async tool results
	s.pendingCalls = calls
	s.pendingResult = make([]ToolResult, len(calls))
	s.resultCount = 0

	// Emit tool_call events
	for _, tc := range calls {
		s.emit(ctx, Event{Type: EventToolCall, TurnNumber: s.turn, Data: tc})
	}

	return calls
}

// BeforeToolCall runs the BeforeToolCall hook for a specific call.
// Returns a non-nil result if the call should be blocked.
// Safe to call from multiple goroutines for parallel tool execution.
func (s *Session) BeforeToolCall(ctx context.Context, call ToolCall) (*BeforeToolCallResult, error) {
	if s.hooks.BeforeToolCall == nil {
		return nil, nil
	}

	s.mu.Lock()
	messages := s.messages
	turn := s.turn
	var assistant Message
	if len(s.messages) > 0 {
		assistant = s.messages[len(s.messages)-1]
	}
	s.mu.Unlock()

	return s.hooks.BeforeToolCall(ctx, BeforeToolCallContext{
		TurnNumber: turn,
		Call:       call,
		Assistant:  assistant,
		Messages:   messages,
	})
}

// HandleToolResult records a tool result and runs the AfterToolCall hook.
// Returns true when all tool results for the current turn have been
// received. Safe to call from multiple goroutines.
func (s *Session) HandleToolResult(ctx context.Context, callID string, result ToolResult) (allDone bool, err error) {
	s.mu.Lock()
	idx := -1
	for i, tc := range s.pendingCalls {
		if tc.ID == callID {
			idx = i
			break
		}
	}
	if idx == -1 {
		s.mu.Unlock()
		return false, fmt.Errorf("unknown tool call ID: %s", callID)
	}

	call := s.pendingCalls[idx]
	turn := s.turn
	var assistant Message
	if len(s.messages) > 0 {
		assistant = s.messages[len(s.messages)-1]
	}
	messages := s.messages
	s.mu.Unlock()

	// AfterToolCall hook (outside lock — may be slow)
	if s.hooks.AfterToolCall != nil {
		after, afterErr := s.hooks.AfterToolCall(ctx, AfterToolCallContext{
			TurnNumber: turn,
			Call:       call,
			Result:     result,
			Assistant:  assistant,
			Messages:   messages,
		})
		if afterErr != nil {
			return false, fmt.Errorf("after tool call %s: %w", call.Name, afterErr)
		}
		if after != nil {
			if after.Content != nil {
				result.Content = *after.Content
			}
			if after.IsError != nil {
				result.IsError = *after.IsError
			}
		}
	}

	s.emit(ctx, Event{Type: EventToolResult, TurnNumber: turn, Data: result})

	s.mu.Lock()
	s.pendingResult[idx] = result
	s.resultCount++
	done := s.resultCount >= len(s.pendingCalls)

	if done {
		// Append all tool result messages to history in order
		for i, tc := range s.pendingCalls {
			s.messages = append(s.messages, ToolResultMessage(tc.ID, s.pendingResult[i].Content, s.pendingResult[i].IsError))
		}

		// Apply dynamic tool changes
		for _, r := range s.pendingResult {
			for _, t := range r.AddTools {
				s.addTool(t)
			}
			for _, name := range r.RemoveTools {
				s.removeTool(name)
			}
		}

		s.emit(ctx, Event{Type: EventTurnEnd, TurnNumber: s.turn, Data: nil})
	}
	s.mu.Unlock()

	return done, nil
}

// ShouldContinue checks whether the session should proceed to another
// turn. Checks the ShouldStop hook and drains follow-ups.
func (s *Session) ShouldContinue(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check custom stop hook
	if s.hooks.ShouldStop != nil {
		var calls []ToolCall
		var results []ToolResult
		var lastAssistant Message
		if len(s.pendingCalls) > 0 {
			calls = s.pendingCalls
			results = s.pendingResult
		}
		for i := len(s.messages) - 1; i >= 0; i-- {
			if s.messages[i].Role == RoleAssistant {
				lastAssistant = s.messages[i]
				break
			}
		}
		if s.hooks.ShouldStop(ctx, StopContext{
			TurnNumber:    s.turn,
			Messages:      s.messages,
			LastAssistant: lastAssistant,
			ToolCalls:     calls,
			ToolResults:   results,
		}) {
			// Check follow-ups before truly stopping
			drained := s.followUp.Drain()
			if len(drained) > 0 {
				s.messages = append(s.messages, drained...)
				return true
			}
			return false
		}
	}

	// No tool calls = natural stop, check follow-ups
	if len(s.pendingCalls) == 0 {
		drained := s.followUp.Drain()
		if len(drained) > 0 {
			s.messages = append(s.messages, drained...)
			return true
		}
		return false
	}

	return true
}

// AdvanceTurn calls PrepareNextTurn hook and increments the turn counter.
func (s *Session) AdvanceTurn(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.hooks.PrepareNextTurn != nil {
		var lastAssistant *Message
		for i := len(s.messages) - 1; i >= 0; i-- {
			if s.messages[i].Role == RoleAssistant {
				lastAssistant = &s.messages[i]
				break
			}
		}
		update, err := s.hooks.PrepareNextTurn(ctx, TurnContext{
			TurnNumber:    s.turn,
			Messages:      s.messages,
			LastAssistant: lastAssistant,
			Tools:         s.tools,
			SystemPrompt:  s.systemPrompt,
		})
		if err != nil {
			return fmt.Errorf("prepare next turn: %w", err)
		}
		if update != nil {
			if update.Tools != nil {
				s.tools = update.Tools
			}
			if update.SystemPrompt != nil {
				s.systemPrompt = *update.SystemPrompt
			}
			if update.Params != nil {
				s.params = update.Params
			}
		}
	}

	s.turn++
	s.pendingCalls = nil
	s.pendingResult = nil
	s.resultCount = 0
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (s *Session) addTool(t ToolDef) {
	for i, existing := range s.tools {
		if existing.Name == t.Name {
			s.tools[i] = t
			return
		}
	}
	s.tools = append(s.tools, t)
}

func (s *Session) removeTool(name string) {
	for i, t := range s.tools {
		if t.Name == name {
			s.tools = append(s.tools[:i], s.tools[i+1:]...)
			return
		}
	}
}

func (s *Session) emit(ctx context.Context, event Event) {
	if s.hooks.OnEvent != nil {
		s.hooks.OnEvent(ctx, event)
	}
}
