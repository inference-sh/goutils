package agentloop

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// mockStreamFn creates a StreamFn that returns responses from a queue.
// Each call pops the next response. Panics if called more times than there
// are responses.
func mockStreamFn(responses ...StreamResponse) StreamFn {
	i := 0
	return func(ctx context.Context, req StreamRequest) (*StreamResponse, error) {
		if i >= len(responses) {
			return nil, fmt.Errorf("unexpected stream call %d", i)
		}
		resp := responses[i]
		i++
		return &resp, nil
	}
}

func textResponse(text string) StreamResponse {
	return StreamResponse{
		Message: TextMessage(RoleAssistant, text),
	}
}

func toolCallResponse(calls ...ToolCall) StreamResponse {
	return StreamResponse{
		Message: Message{
			Role: RoleAssistant,
			Content: []Content{
				{Type: ContentText, Text: "I'll use tools"},
				{Type: ContentToolCalls, ToolCalls: calls},
			},
		},
	}
}

func echoExecutor(ctx context.Context, call ToolCall) (ToolResult, error) {
	return ToolResult{Content: fmt.Sprintf("result of %s", call.Name)}, nil
}

// ---------------------------------------------------------------------------
// Basic loop tests
// ---------------------------------------------------------------------------

func TestRun_SingleTurn_NoTools(t *testing.T) {
	stream := mockStreamFn(textResponse("Hello!"))

	loop := New(stream, echoExecutor)
	msgs, err := loop.Run(context.Background(), []Message{
		TextMessage(RoleUser, "Hi"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have: user + assistant
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if msgs[1].Role != RoleAssistant {
		t.Errorf("expected assistant role, got %s", msgs[1].Role)
	}
	if msgs[1].Text() != "Hello!" {
		t.Errorf("expected 'Hello!', got %q", msgs[1].Text())
	}
}

func TestRun_ToolCallThenResponse(t *testing.T) {
	tc := ToolCall{ID: "call-1", Name: "search", Arguments: map[string]any{"q": "test"}}

	stream := mockStreamFn(
		toolCallResponse(tc),
		textResponse("Found results"),
	)

	loop := New(stream, echoExecutor)
	msgs, err := loop.Run(context.Background(), []Message{
		TextMessage(RoleUser, "Search for test"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// user + assistant(tool_call) + tool_result + assistant(text)
	if len(msgs) != 4 {
		t.Fatalf("expected 4 messages, got %d", len(msgs))
	}
	if msgs[2].Role != RoleTool {
		t.Errorf("expected tool role at index 2, got %s", msgs[2].Role)
	}
	if msgs[3].Text() != "Found results" {
		t.Errorf("expected 'Found results', got %q", msgs[3].Text())
	}
}

func TestRun_MaxTurns(t *testing.T) {
	tc := ToolCall{ID: "call-1", Name: "loop", Arguments: nil}
	callCount := 0
	stream := func(ctx context.Context, req StreamRequest) (*StreamResponse, error) {
		callCount++
		return &StreamResponse{Message: Message{
			Role: RoleAssistant,
			Content: []Content{
				{Type: ContentText, Text: "again"},
				{Type: ContentToolCalls, ToolCalls: []ToolCall{tc}},
			},
		}}, nil
	}

	loop := New(stream, echoExecutor, WithMaxTurns(3))
	_, err := loop.Run(context.Background(), []Message{
		TextMessage(RoleUser, "go"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 3 {
		t.Errorf("expected 3 stream calls, got %d", callCount)
	}
}

func TestRun_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	stream := mockStreamFn(textResponse("never"))
	loop := New(stream, echoExecutor)
	_, err := loop.Run(ctx, []Message{TextMessage(RoleUser, "Hi")})
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestRun_AlreadyRunning(t *testing.T) {
	started := make(chan struct{})
	stream := func(ctx context.Context, req StreamRequest) (*StreamResponse, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	loop := New(stream, echoExecutor)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go loop.Run(ctx, []Message{TextMessage(RoleUser, "Hi")})

	<-started // wait until stream is entered (loop is definitely running)

	_, err := loop.Run(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Errorf("expected 'already running' error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Hook tests
// ---------------------------------------------------------------------------

func TestHook_BeforeToolCall_Block(t *testing.T) {
	tc := ToolCall{ID: "call-1", Name: "dangerous", Arguments: nil}
	stream := mockStreamFn(
		toolCallResponse(tc),
		textResponse("ok"),
	)

	executorCalled := false
	executor := func(ctx context.Context, call ToolCall) (ToolResult, error) {
		executorCalled = true
		return ToolResult{Content: "done"}, nil
	}

	loop := New(stream, executor, WithHooks(Hooks{
		BeforeToolCall: func(ctx context.Context, tc BeforeToolCallContext) (*BeforeToolCallResult, error) {
			if tc.Call.Name == "dangerous" {
				return &BeforeToolCallResult{Block: true, Reason: "too risky"}, nil
			}
			return nil, nil
		},
	}))

	msgs, err := loop.Run(context.Background(), []Message{TextMessage(RoleUser, "do it")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if executorCalled {
		t.Error("executor should not have been called for blocked tool")
	}

	// Check the tool result is an error
	toolMsg := msgs[2] // user, assistant(tc), tool_result
	if toolMsg.Role != RoleTool {
		t.Errorf("expected tool role, got %s", toolMsg.Role)
	}
	if toolMsg.Content[0].Text != "too risky" {
		t.Errorf("expected 'too risky', got %q", toolMsg.Content[0].Text)
	}
}

func TestHook_AfterToolCall_ModifyResult(t *testing.T) {
	tc := ToolCall{ID: "call-1", Name: "search", Arguments: nil}
	stream := mockStreamFn(
		toolCallResponse(tc),
		textResponse("done"),
	)

	loop := New(stream, echoExecutor, WithHooks(Hooks{
		AfterToolCall: func(ctx context.Context, tc AfterToolCallContext) (*AfterToolCallResult, error) {
			modified := "MODIFIED: " + tc.Result.Content
			return &AfterToolCallResult{Content: &modified}, nil
		},
	}))

	msgs, err := loop.Run(context.Background(), []Message{TextMessage(RoleUser, "go")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	toolResult := msgs[2]
	if !strings.HasPrefix(toolResult.Content[0].Text, "MODIFIED:") {
		t.Errorf("expected modified result, got %q", toolResult.Content[0].Text)
	}
}

func TestHook_PrepareNextTurn_SwapTools(t *testing.T) {
	tc1 := ToolCall{ID: "call-1", Name: "step1", Arguments: nil}
	tc2 := ToolCall{ID: "call-2", Name: "step2", Arguments: nil}

	var capturedTools [][]ToolDef
	stream := func(ctx context.Context, req StreamRequest) (*StreamResponse, error) {
		capturedTools = append(capturedTools, req.Tools)
		if len(capturedTools) == 1 {
			return &StreamResponse{Message: Message{
				Role:    RoleAssistant,
				Content: []Content{{Type: ContentToolCalls, ToolCalls: []ToolCall{tc1}}},
			}}, nil
		}
		if len(capturedTools) == 2 {
			return &StreamResponse{Message: Message{
				Role:    RoleAssistant,
				Content: []Content{{Type: ContentToolCalls, ToolCalls: []ToolCall{tc2}}},
			}}, nil
		}
		return &StreamResponse{Message: TextMessage(RoleAssistant, "done")}, nil
	}

	initialTools := []ToolDef{{Name: "step1", Description: "first"}}
	nextTools := []ToolDef{{Name: "step2", Description: "second"}}

	loop := New(stream, echoExecutor,
		WithTools(initialTools),
		WithHooks(Hooks{
			PrepareNextTurn: func(ctx context.Context, tc TurnContext) (*TurnUpdate, error) {
				if tc.TurnNumber == 0 {
					return &TurnUpdate{Tools: nextTools}, nil
				}
				return nil, nil
			},
		}),
	)

	_, err := loop.Run(context.Background(), []Message{TextMessage(RoleUser, "go")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(capturedTools) < 2 {
		t.Fatalf("expected at least 2 stream calls, got %d", len(capturedTools))
	}
	if capturedTools[0][0].Name != "step1" {
		t.Errorf("first call should have step1 tool, got %s", capturedTools[0][0].Name)
	}
	if capturedTools[1][0].Name != "step2" {
		t.Errorf("second call should have step2 tool, got %s", capturedTools[1][0].Name)
	}
}

func TestHook_ShouldStop_Custom(t *testing.T) {
	tc := ToolCall{ID: "call-1", Name: "check", Arguments: nil}
	callCount := 0
	stream := func(ctx context.Context, req StreamRequest) (*StreamResponse, error) {
		callCount++
		return &StreamResponse{Message: Message{
			Role: RoleAssistant,
			Content: []Content{
				{Type: ContentText, Text: "checking"},
				{Type: ContentToolCalls, ToolCalls: []ToolCall{tc}},
			},
		}}, nil
	}

	loop := New(stream, echoExecutor,
		WithMaxTurns(100),
		WithHooks(Hooks{
			ShouldStop: func(ctx context.Context, sc StopContext) bool {
				return sc.TurnNumber >= 2
			},
		}),
	)

	_, err := loop.Run(context.Background(), []Message{TextMessage(RoleUser, "go")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 3 { // turns 0, 1, 2 then stop
		t.Errorf("expected 3 calls, got %d", callCount)
	}
}

func TestHook_OnEvent_Lifecycle(t *testing.T) {
	stream := mockStreamFn(textResponse("hi"))
	var events []EventType

	loop := New(stream, echoExecutor, WithHooks(Hooks{
		OnEvent: func(ctx context.Context, event Event) {
			events = append(events, event.Type)
		},
	}))

	loop.Run(context.Background(), []Message{TextMessage(RoleUser, "hi")})

	expected := []EventType{EventLoopStart, EventTurnStart, EventTurnEnd, EventLoopEnd}
	if len(events) != len(expected) {
		t.Fatalf("expected %d events, got %d: %v", len(expected), len(events), events)
	}
	for i, e := range expected {
		if events[i] != e {
			t.Errorf("event %d: expected %s, got %s", i, e, events[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Queue and follow-up tests
// ---------------------------------------------------------------------------

func TestQueueMessage_InjectBetweenTurns(t *testing.T) {
	tc := ToolCall{ID: "call-1", Name: "work", Arguments: nil}
	callCount := 0

	stream := func(ctx context.Context, req StreamRequest) (*StreamResponse, error) {
		callCount++
		if callCount == 1 {
			return &StreamResponse{Message: Message{
				Role: RoleAssistant,
				Content: []Content{
					{Type: ContentToolCalls, ToolCalls: []ToolCall{tc}},
				},
			}}, nil
		}
		return &StreamResponse{Message: TextMessage(RoleAssistant, "done")}, nil
	}

	loop := New(stream, echoExecutor)

	loop.QueueMessage(TextMessage(RoleUser, "also consider X"))

	msgs, err := loop.Run(context.Background(), []Message{TextMessage(RoleUser, "start")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, m := range msgs {
		if m.Text() == "also consider X" {
			found = true
			break
		}
	}
	if !found {
		t.Error("queued message not found in history")
	}
}

func TestFollowUp_ContinuesAfterStop(t *testing.T) {
	callCount := int32(0)

	stream := func(ctx context.Context, req StreamRequest) (*StreamResponse, error) {
		n := atomic.AddInt32(&callCount, 1)
		return &StreamResponse{
			Message: TextMessage(RoleAssistant, fmt.Sprintf("response %d", n)),
		}, nil
	}

	loop := New(stream, echoExecutor)
	loop.FollowUp(TextMessage(RoleUser, "one more thing"))

	msgs, err := loop.Run(context.Background(), []Message{TextMessage(RoleUser, "hello")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have: user + assistant1 + follow-up + assistant2
	if atomic.LoadInt32(&callCount) != 2 {
		t.Errorf("expected 2 stream calls (initial + follow-up), got %d", callCount)
	}

	found := false
	for _, m := range msgs {
		if m.Text() == "one more thing" {
			found = true
			break
		}
	}
	if !found {
		t.Error("follow-up message not found in history")
	}
	if len(msgs) < 4 {
		t.Errorf("expected at least 4 messages, got %d", len(msgs))
	}
}

// ---------------------------------------------------------------------------
// Dynamic tool changes
// ---------------------------------------------------------------------------

func TestDynamicTools_AddAndRemove(t *testing.T) {
	tc := ToolCall{ID: "call-1", Name: "setup", Arguments: nil}

	var secondCallTools []ToolDef
	callCount := 0
	stream := func(ctx context.Context, req StreamRequest) (*StreamResponse, error) {
		callCount++
		if callCount == 1 {
			return &StreamResponse{Message: Message{
				Role:    RoleAssistant,
				Content: []Content{{Type: ContentToolCalls, ToolCalls: []ToolCall{tc}}},
			}}, nil
		}
		secondCallTools = req.Tools
		return &StreamResponse{Message: TextMessage(RoleAssistant, "done")}, nil
	}

	executor := func(ctx context.Context, call ToolCall) (ToolResult, error) {
		return ToolResult{
			Content:     "setup complete",
			AddTools:    []ToolDef{{Name: "new_tool", Description: "freshly added"}},
			RemoveTools: []string{"setup"},
		}, nil
	}

	loop := New(stream, executor, WithTools([]ToolDef{
		{Name: "setup", Description: "initial"},
	}))

	_, err := loop.Run(context.Background(), []Message{TextMessage(RoleUser, "go")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(secondCallTools) != 1 {
		t.Fatalf("expected 1 tool on second call, got %d", len(secondCallTools))
	}
	if secondCallTools[0].Name != "new_tool" {
		t.Errorf("expected new_tool, got %s", secondCallTools[0].Name)
	}
}

// ---------------------------------------------------------------------------
// Parallel tool execution
// ---------------------------------------------------------------------------

func TestParallelToolExecution(t *testing.T) {
	calls := []ToolCall{
		{ID: "c1", Name: "a", Arguments: nil},
		{ID: "c2", Name: "b", Arguments: nil},
		{ID: "c3", Name: "c", Arguments: nil},
	}

	stream := mockStreamFn(
		toolCallResponse(calls...),
		textResponse("done"),
	)

	var executed int32
	executor := func(ctx context.Context, call ToolCall) (ToolResult, error) {
		atomic.AddInt32(&executed, 1)
		return ToolResult{Content: "ok"}, nil
	}

	loop := New(stream, executor, WithToolExecution(ToolExecParallel))
	_, err := loop.Run(context.Background(), []Message{TextMessage(RoleUser, "go")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if atomic.LoadInt32(&executed) != 3 {
		t.Errorf("expected 3 executions, got %d", executed)
	}
}
