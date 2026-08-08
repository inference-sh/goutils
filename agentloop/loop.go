package agentloop

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// Loop is a synchronous driver for Session. It calls StreamFn and
// ToolExecutor in a blocking for-loop — suitable for CLI agents.
//
// For async/event-driven agents (servers), use Session directly and
// drive it from your event handlers.
type Loop struct {
	session  *Session
	streamFn StreamFn
	executor ToolExecutor
	toolExec ToolExecutionMode

	mu      sync.Mutex
	running bool
}

// ToolExecutionMode controls whether tool calls run sequentially or in parallel.
type ToolExecutionMode int

const (
	ToolExecSequential ToolExecutionMode = iota
	ToolExecParallel
)

// Option configures a Loop.
type Option func(*Loop)

func WithHooks(h Hooks) Option            { return func(l *Loop) { l.session.hooks = h } }
func WithSystemPrompt(s string) Option    { return func(l *Loop) { l.session.systemPrompt = s } }
func WithTools(t []ToolDef) Option        { return func(l *Loop) { l.session.tools = t } }
func WithMaxTurns(n int) Option           { return func(l *Loop) { l.session.maxTurns = n } }
func WithParams(p any) Option             { return func(l *Loop) { l.session.params = p } }
func WithToolExecution(m ToolExecutionMode) Option { return func(l *Loop) { l.toolExec = m } }
func WithSteeringMode(m QueueMode) Option {
	return func(l *Loop) { l.session.steering = newMessageQueue(m) }
}
func WithFollowUpMode(m QueueMode) Option {
	return func(l *Loop) { l.session.followUp = newMessageQueue(m) }
}
func WithCompaction(cfg CompactionConfig) Option {
	return func(l *Loop) { l.session.compaction = &cfg }
}

// New creates a Loop. The streamFn and executor are required — everything
// else is configured via options.
func New(streamFn StreamFn, executor ToolExecutor, opts ...Option) *Loop {
	l := &Loop{
		session:  NewSession(nil),
		streamFn: streamFn,
		executor: executor,
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// Session returns the underlying Session for direct access.
func (l *Loop) Session() *Session {
	return l.session
}

// Steer injects a message between turns while the loop is running.
// Thread-safe.
func (l *Loop) Steer(msg Message) {
	l.session.Steer(msg)
}

// FollowUp queues a message for after the loop would stop.
func (l *Loop) FollowUp(msg Message) {
	l.session.FollowUp(msg)
}

// Run executes the sync agent loop starting from the given messages.
// Returns the full conversation history on completion.
func (l *Loop) Run(ctx context.Context, messages []Message) ([]Message, error) {
	l.mu.Lock()
	if l.running {
		l.mu.Unlock()
		return nil, fmt.Errorf("loop already running")
	}
	l.running = true
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.running = false
		l.mu.Unlock()
	}()

	// Set initial messages on the session
	l.session.mu.Lock()
	l.session.messages = messages
	l.session.turn = 0
	l.session.mu.Unlock()

	l.session.emit(ctx, Event{Type: EventLoopStart})

	for {
		if err := ctx.Err(); err != nil {
			l.session.emit(ctx, Event{Type: EventLoopError, Data: err})
			return l.session.Messages(), err
		}

		// Build the LLM request (steering, compaction, context transform)
		req, err := l.session.NextRequest(ctx)
		if err != nil {
			return l.session.Messages(), err
		}
		if req == nil {
			// maxTurns exceeded
			return l.session.Messages(), nil
		}

		// Call the LLM
		resp, err := l.streamFn(ctx, *req)
		if err != nil {
			l.session.emit(ctx, Event{Type: EventLoopError, Data: err})
			return l.session.Messages(), fmt.Errorf("stream: %w", err)
		}

		// Process the response
		toolCalls := l.session.HandleResponse(ctx, *resp)

		if len(toolCalls) == 0 {
			// No tool calls — check if we should continue
			if !l.session.ShouldContinue(ctx) {
				l.session.emit(ctx, Event{Type: EventLoopEnd})
				return l.session.Messages(), nil
			}
			l.session.AdvanceTurn(ctx)
			continue
		}

		// Execute tools (sync — sequential or parallel)
		if err := l.executeToolsSync(ctx, toolCalls); err != nil {
			return l.session.Messages(), err
		}

		// Check stop condition
		if !l.session.ShouldContinue(ctx) {
			l.session.emit(ctx, Event{Type: EventLoopEnd})
			return l.session.Messages(), nil
		}

		l.session.AdvanceTurn(ctx)
	}
}

// executeToolsSync runs tool calls synchronously (blocking).
func (l *Loop) executeToolsSync(ctx context.Context, calls []ToolCall) error {
	exec := func(tc ToolCall) error {
		// Before hook
		before, err := l.session.BeforeToolCall(ctx, tc)
		if err != nil {
			return err
		}

		var result ToolResult
		if before != nil && before.Block {
			reason := before.Reason
			if reason == "" {
				reason = "tool call blocked"
			}
			result = ToolResult{Content: reason, IsError: true}
		} else {
			result, err = l.executor(ctx, tc)
			if err != nil {
				result = ToolResult{Content: err.Error(), IsError: true}
			}
		}

		_, err = l.session.HandleToolResult(ctx, tc.ID, result)
		return err
	}

	if l.toolExec == ToolExecParallel && len(calls) > 1 {
		sem := make(chan struct{}, maxParallel(len(calls)))
		var wg sync.WaitGroup
		var firstErr atomic.Value
		execCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		for _, tc := range calls {
			wg.Add(1)
			go func(tc ToolCall) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				if execCtx.Err() != nil {
					return
				}
				if err := exec(tc); err != nil {
					firstErr.CompareAndSwap(nil, err)
					cancel()
				}
			}(tc)
		}
		wg.Wait()
		if v := firstErr.Load(); v != nil {
			return v.(error)
		}
	} else {
		for _, tc := range calls {
			if err := exec(tc); err != nil {
				return err
			}
		}
	}

	return nil
}

func maxParallel(n int) int {
	const cap = 16
	if n < cap {
		return n
	}
	return cap
}

func defaultConvertToLLM(messages []Message) []Message {
	out := make([]Message, 0, len(messages))
	for _, m := range messages {
		// Skip system messages — SystemPrompt is passed separately in StreamRequest.
		if m.Role == RoleSystem {
			continue
		}
		if m.Role.IsLLMRole() {
			out = append(out, m)
		}
	}
	return out
}
