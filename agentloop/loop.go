package agentloop

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// Loop is the core agent turn loop. It alternates between LLM calls and tool
// execution until the agent is done, an error occurs, or the context is
// cancelled.
//
// Create with New, configure with options, then call Run.
type Loop struct {
	streamFn     StreamFn
	executor     ToolExecutor
	hooks        Hooks
	systemPrompt string
	tools        []ToolDef
	params       any
	maxTurns     int
	toolExec     ToolExecutionMode
	compaction   *CompactionConfig

	steering *messageQueue
	followUp *messageQueue

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

func WithHooks(h Hooks) Option                      { return func(l *Loop) { l.hooks = h } }
func WithSystemPrompt(s string) Option              { return func(l *Loop) { l.systemPrompt = s } }
func WithTools(t []ToolDef) Option                  { return func(l *Loop) { l.tools = t } }
func WithMaxTurns(n int) Option                     { return func(l *Loop) { l.maxTurns = n } }
func WithSteeringMode(m QueueMode) Option           { return func(l *Loop) { l.steering = newMessageQueue(m) } }
func WithFollowUpMode(m QueueMode) Option           { return func(l *Loop) { l.followUp = newMessageQueue(m) } }
func WithToolExecution(m ToolExecutionMode) Option   { return func(l *Loop) { l.toolExec = m } }
func WithCompaction(cfg CompactionConfig) Option     { return func(l *Loop) { l.compaction = &cfg } }
func WithParams(p any) Option                        { return func(l *Loop) { l.params = p } }

// New creates a Loop. The streamFn and executor are required — everything
// else is configured via options.
func New(streamFn StreamFn, executor ToolExecutor, opts ...Option) *Loop {
	l := &Loop{
		streamFn: streamFn,
		executor: executor,
		maxTurns: 100,
		steering: newMessageQueue(QueueAll),
		followUp: newMessageQueue(QueueAll),
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// Steer injects a message between turns while the loop is running.
// Thread-safe — can be called from any goroutine (webhooks, UI events, etc).
func (l *Loop) Steer(msg Message) {
	l.steering.Enqueue(msg)
}

// FollowUp queues a message that is processed only after the loop would
// otherwise stop. If the loop has pending follow-ups when it reaches a
// natural stop, it drains them and continues.
func (l *Loop) FollowUp(msg Message) {
	l.followUp.Enqueue(msg)
}

// Run executes the agent loop starting from the given messages.
//
// The loop:
//  1. Injects any pending steering messages
//  2. Calls TransformContext + ConvertToLLM + StreamFn
//  3. Extracts tool calls from the response
//  4. Runs BeforeToolCall → ToolExecutor → AfterToolCall for each
//  5. Calls ShouldStop — if false, calls PrepareNextTurn and repeats
//  6. On natural stop, checks follow-up queue — if non-empty, continues
//
// Returns nil on clean completion, context.Canceled on abort, or the
// first unrecoverable error.
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

	l.emit(ctx, Event{Type: EventLoopStart})

	turn := 0

	for {
		// Check context before each turn
		if err := ctx.Err(); err != nil {
			l.emit(ctx, Event{Type: EventLoopError, TurnNumber: turn, Data: err})
			return messages, err
		}

		// Guard against runaway loops
		if turn >= l.maxTurns {
			l.emit(ctx, Event{Type: EventLoopEnd, TurnNumber: turn, Data: "max_turns"})
			return messages, nil
		}

		// Drain steering queue
		for _, msg := range l.steering.Drain() {
			messages = append(messages, msg)
			l.emit(ctx, Event{Type: EventSteerInject, TurnNumber: turn, Data: msg})
		}

		// Auto-compact if configured
		if l.compaction != nil {
			compacted, cr, compactErr := AutoCompact(ctx, messages, *l.compaction)
			if compactErr != nil {
				l.emit(ctx, Event{Type: EventLoopError, TurnNumber: turn, Data: compactErr})
			} else if cr != nil {
				messages = compacted
				l.emit(ctx, Event{Type: EventCompaction, TurnNumber: turn, Data: cr})
			}
		}

		l.emit(ctx, Event{Type: EventTurnStart, TurnNumber: turn})

		// Transform context
		llmMessages := messages
		if l.hooks.TransformContext != nil {
			var err error
			llmMessages, err = l.hooks.TransformContext(ctx, messages)
			if err != nil {
				l.emit(ctx, Event{Type: EventLoopError, TurnNumber: turn, Data: err})
				return messages, fmt.Errorf("transform context: %w", err)
			}
		}

		// Convert to LLM wire format
		if l.hooks.ConvertToLLM != nil {
			var convertErr error
			llmMessages, convertErr = l.hooks.ConvertToLLM(ctx, llmMessages)
			if convertErr != nil {
				l.emit(ctx, Event{Type: EventLoopError, TurnNumber: turn, Data: convertErr})
				return messages, fmt.Errorf("convert to llm: %w", convertErr)
			}
		} else {
			llmMessages = defaultConvertToLLM(llmMessages)
		}

		// Call the LLM
		resp, err := l.streamFn(ctx, StreamRequest{
			SystemPrompt: l.systemPrompt,
			Messages:     llmMessages,
			Tools:        l.tools,
			Params:       l.params,
		})
		if err != nil {
			l.emit(ctx, Event{Type: EventLoopError, TurnNumber: turn, Data: err})
			return messages, fmt.Errorf("stream: %w", err)
		}

		// Append assistant message to history
		messages = append(messages, resp.Message)
		toolCalls := resp.Message.ToolCalls()

		// No tool calls — check stop condition
		if len(toolCalls) == 0 {
			l.emit(ctx, Event{Type: EventTurnEnd, TurnNumber: turn, Data: resp.Usage})

			if !l.drainFollowUps(&messages) {
				l.emit(ctx, Event{Type: EventLoopEnd, TurnNumber: turn})
				return messages, nil
			}
			turn++
			continue
		}

		// Execute tool calls
		results, terminate, err := l.executeTools(ctx, turn, toolCalls, resp.Message, messages)
		if err != nil {
			l.emit(ctx, Event{Type: EventLoopError, TurnNumber: turn, Data: err})
			return messages, fmt.Errorf("tool execution: %w", err)
		}

		// Append tool result messages to history
		for i, tc := range toolCalls {
			if i < len(results) {
				messages = append(messages, ToolResultMessage(tc.ID, results[i].Content, results[i].IsError))
			}
		}

		// Apply dynamic tool changes from results
		l.applyToolChanges(results)

		l.emit(ctx, Event{Type: EventTurnEnd, TurnNumber: turn, Data: resp.Usage})

		// Check stop — terminate hint or custom hook
		if terminate || l.shouldStop(ctx, turn, messages, resp.Message, toolCalls, results) {
			if !l.drainFollowUps(&messages) {
				l.emit(ctx, Event{Type: EventLoopEnd, TurnNumber: turn})
				return messages, nil
			}
		}

		// Prepare next turn — let consumer swap tools, prompt, or stream fn
		if l.hooks.PrepareNextTurn != nil {
			update, err := l.hooks.PrepareNextTurn(ctx, TurnContext{
				TurnNumber:    turn,
				Messages:      messages,
				LastAssistant: &resp.Message,
				Tools:         l.tools,
				SystemPrompt:  l.systemPrompt,
			})
			if err != nil {
				l.emit(ctx, Event{Type: EventLoopError, TurnNumber: turn, Data: err})
				return messages, fmt.Errorf("prepare next turn: %w", err)
			}
			if update != nil {
				l.applyTurnUpdate(update)
			}
		}

		turn++
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (l *Loop) executeTools(ctx context.Context, turn int, calls []ToolCall, assistant Message, messages []Message) ([]ToolResult, bool, error) {
	results := make([]ToolResult, len(calls))
	terminateFlags := make([]bool, len(calls))

	exec := func(i int, tc ToolCall) error {
		l.emit(ctx, Event{Type: EventToolCall, TurnNumber: turn, Data: tc})

		// Before hook
		if l.hooks.BeforeToolCall != nil {
			before, err := l.hooks.BeforeToolCall(ctx, BeforeToolCallContext{
				TurnNumber: turn,
				Call:       tc,
				Assistant:  assistant,
				Messages:   messages,
			})
			if err != nil {
				return fmt.Errorf("before tool call %s: %w", tc.Name, err)
			}
			if before != nil && before.Block {
				reason := before.Reason
				if reason == "" {
					reason = "tool call blocked"
				}
				results[i] = ToolResult{Content: reason, IsError: true}
				terminateFlags[i] = before.Terminate
				l.emit(ctx, Event{Type: EventToolResult, TurnNumber: turn, Data: results[i]})
				return nil
			}
		}

		// Execute
		result, err := l.executor(ctx, tc)
		if err != nil {
			result = ToolResult{Content: err.Error(), IsError: true}
		}

		// After hook
		if l.hooks.AfterToolCall != nil {
			after, afterErr := l.hooks.AfterToolCall(ctx, AfterToolCallContext{
				TurnNumber: turn,
				Call:       tc,
				Result:     result,
				Assistant:  assistant,
				Messages:   messages,
			})
			if afterErr != nil {
				return fmt.Errorf("after tool call %s: %w", tc.Name, afterErr)
			}
			if after != nil {
				if after.Content != nil {
					result.Content = *after.Content
				}
				if after.IsError != nil {
					result.IsError = *after.IsError
				}
				terminateFlags[i] = after.Terminate
			}
		}

		results[i] = result
		l.emit(ctx, Event{Type: EventToolResult, TurnNumber: turn, Data: result})
		return nil
	}

	if l.toolExec == ToolExecParallel && len(calls) > 1 {
		sem := make(chan struct{}, maxParallel(len(calls)))
		var wg sync.WaitGroup
		var firstErr atomic.Value
		execCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		for i, tc := range calls {
			wg.Add(1)
			go func(i int, tc ToolCall) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				if execCtx.Err() != nil {
					return
				}
				if err := exec(i, tc); err != nil {
					firstErr.CompareAndSwap(nil, err)
					cancel()
				}
			}(i, tc)
		}
		wg.Wait()
		if v := firstErr.Load(); v != nil {
			return results, false, v.(error)
		}
	} else {
		for i, tc := range calls {
			if err := exec(i, tc); err != nil {
				return results, false, err
			}
		}
	}

	allTerminate := len(calls) > 0
	for _, t := range terminateFlags {
		if !t {
			allTerminate = false
			break
		}
	}

	return results, allTerminate, nil
}

func maxParallel(n int) int {
	const cap = 16
	if n < cap {
		return n
	}
	return cap
}

func (l *Loop) shouldStop(ctx context.Context, turn int, messages []Message, assistant Message, calls []ToolCall, results []ToolResult) bool {
	if l.hooks.ShouldStop != nil {
		return l.hooks.ShouldStop(ctx, StopContext{
			TurnNumber:    turn,
			Messages:      messages,
			LastAssistant: assistant,
			ToolCalls:     calls,
			ToolResults:   results,
		})
	}
	// Only called from the tool-calls-present branch; no-tool-call stops
	// are handled earlier in Run(). Default: keep going after tool results.
	return false
}

func (l *Loop) drainFollowUps(messages *[]Message) bool {
	drained := l.followUp.Drain()
	if len(drained) == 0 {
		return false
	}
	*messages = append(*messages, drained...)
	return true
}

func (l *Loop) applyTurnUpdate(update *TurnUpdate) {
	if update.Tools != nil {
		l.tools = update.Tools
	}
	if update.SystemPrompt != nil {
		l.systemPrompt = *update.SystemPrompt
	}
	if update.StreamFn != nil {
		l.streamFn = update.StreamFn
	}
	if update.Params != nil {
		l.params = update.Params
	}
}

func (l *Loop) applyToolChanges(results []ToolResult) {
	for _, r := range results {
		for _, t := range r.AddTools {
			l.addTool(t)
		}
		for _, name := range r.RemoveTools {
			l.removeTool(name)
		}
	}
}

func (l *Loop) addTool(t ToolDef) {
	for i, existing := range l.tools {
		if existing.Name == t.Name {
			l.tools[i] = t
			return
		}
	}
	l.tools = append(l.tools, t)
}

func (l *Loop) removeTool(name string) {
	for i, t := range l.tools {
		if t.Name == name {
			l.tools = append(l.tools[:i], l.tools[i+1:]...)
			return
		}
	}
}

func (l *Loop) emit(ctx context.Context, event Event) {
	if l.hooks.OnEvent != nil {
		l.hooks.OnEvent(ctx, event)
	}
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
