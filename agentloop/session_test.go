package agentloop

import (
	"context"
	"testing"
)

func TestSession_AsyncPattern(t *testing.T) {
	// This test demonstrates the async event-driven pattern:
	// NextRequest → (async LLM call) → HandleResponse →
	// (async tool execution) → HandleToolResult → ShouldContinue → AdvanceTurn

	session := NewSession(
		[]Message{TextMessage(RoleUser, "search for Go")},
		WithSessionSystemPrompt("You are helpful."),
		WithSessionTools([]ToolDef{{Name: "search", Description: "search"}}),
	)
	ctx := context.Background()

	// Turn 1: get the LLM request
	req, err := session.NextRequest(ctx)
	if err != nil {
		t.Fatalf("NextRequest: %v", err)
	}
	if req == nil {
		t.Fatal("expected non-nil request")
	}
	if req.SystemPrompt != "You are helpful." {
		t.Errorf("expected system prompt, got %q", req.SystemPrompt)
	}

	// Simulate LLM response with a tool call
	resp := StreamResponse{
		Message: Message{
			Role: RoleAssistant,
			Content: []Content{
				{Type: ContentText, Text: "I'll search"},
				{Type: ContentToolCalls, ToolCalls: []ToolCall{
					{ID: "call-1", Name: "search", Arguments: map[string]any{"q": "Go"}},
				}},
			},
		},
	}

	calls := session.HandleResponse(ctx, resp)
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(calls))
	}
	if calls[0].Name != "search" {
		t.Errorf("expected 'search', got %s", calls[0].Name)
	}

	// Simulate async tool execution completing
	done, err := session.HandleToolResult(ctx, "call-1", ToolResult{Content: "found Go docs"})
	if err != nil {
		t.Fatalf("HandleToolResult: %v", err)
	}
	if !done {
		t.Error("expected all tools done after single result")
	}

	// Check should continue
	if !session.ShouldContinue(ctx) {
		t.Error("expected ShouldContinue true after tool results")
	}

	// Advance turn
	if err := session.AdvanceTurn(ctx); err != nil {
		t.Fatalf("AdvanceTurn: %v", err)
	}
	if session.Turn() != 1 {
		t.Errorf("expected turn 1, got %d", session.Turn())
	}

	// Turn 2: get next request
	req2, err := session.NextRequest(ctx)
	if err != nil {
		t.Fatalf("NextRequest turn 2: %v", err)
	}
	if req2 == nil {
		t.Fatal("expected non-nil request for turn 2")
	}

	// Simulate final response (no tool calls)
	resp2 := StreamResponse{
		Message: TextMessage(RoleAssistant, "Here are the Go docs"),
	}
	calls2 := session.HandleResponse(ctx, resp2)
	if len(calls2) != 0 {
		t.Errorf("expected no tool calls, got %d", len(calls2))
	}

	// Should stop now (no tool calls, no follow-ups)
	if session.ShouldContinue(ctx) {
		t.Error("expected ShouldContinue false on final turn")
	}

	// Verify conversation history
	msgs := session.Messages()
	if len(msgs) < 4 {
		t.Fatalf("expected at least 4 messages (user, assistant+tc, tool_result, assistant), got %d", len(msgs))
	}
}

func TestSession_ParallelToolResults(t *testing.T) {
	session := NewSession(
		[]Message{TextMessage(RoleUser, "search both")},
		WithSessionTools([]ToolDef{
			{Name: "search_a", Description: "a"},
			{Name: "search_b", Description: "b"},
		}),
	)
	ctx := context.Background()

	req, _ := session.NextRequest(ctx)
	if req == nil {
		t.Fatal("expected request")
	}

	// LLM returns two tool calls
	calls := session.HandleResponse(ctx, StreamResponse{
		Message: Message{
			Role: RoleAssistant,
			Content: []Content{{Type: ContentToolCalls, ToolCalls: []ToolCall{
				{ID: "c1", Name: "search_a", Arguments: nil},
				{ID: "c2", Name: "search_b", Arguments: nil},
			}}},
		},
	})
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}

	// Results arrive out of order (async)
	done1, err := session.HandleToolResult(ctx, "c2", ToolResult{Content: "b result"})
	if err != nil {
		t.Fatalf("HandleToolResult c2: %v", err)
	}
	if done1 {
		t.Error("should not be done after first result")
	}

	done2, err := session.HandleToolResult(ctx, "c1", ToolResult{Content: "a result"})
	if err != nil {
		t.Fatalf("HandleToolResult c1: %v", err)
	}
	if !done2 {
		t.Error("should be done after second result")
	}

	// Results should be in original call order in history
	msgs := session.Messages()
	// user + assistant + tool_result(c1) + tool_result(c2)
	toolResults := []Message{}
	for _, m := range msgs {
		if m.Role == RoleTool {
			toolResults = append(toolResults, m)
		}
	}
	if len(toolResults) != 2 {
		t.Fatalf("expected 2 tool results, got %d", len(toolResults))
	}
	// c1 should come first (original order), even though c2 finished first
	if toolResults[0].Content[0].ToolCallID != "c1" {
		t.Errorf("expected c1 first, got %s", toolResults[0].Content[0].ToolCallID)
	}
	if toolResults[1].Content[0].ToolCallID != "c2" {
		t.Errorf("expected c2 second, got %s", toolResults[1].Content[0].ToolCallID)
	}
}

func TestSession_BeforeToolCall_Block(t *testing.T) {
	session := NewSession(
		[]Message{TextMessage(RoleUser, "do it")},
		WithSessionHooks(Hooks{
			BeforeToolCall: func(ctx context.Context, tc BeforeToolCallContext) (*BeforeToolCallResult, error) {
				if tc.Call.Name == "dangerous" {
					return &BeforeToolCallResult{Block: true, Reason: "too risky"}, nil
				}
				return nil, nil
			},
		}),
	)
	ctx := context.Background()

	before, err := session.BeforeToolCall(ctx, ToolCall{ID: "c1", Name: "dangerous"})
	if err != nil {
		t.Fatalf("BeforeToolCall: %v", err)
	}
	if before == nil || !before.Block {
		t.Error("expected block")
	}
	if before.Reason != "too risky" {
		t.Errorf("expected 'too risky', got %q", before.Reason)
	}

	// Safe tool should pass
	before2, _ := session.BeforeToolCall(ctx, ToolCall{ID: "c2", Name: "safe"})
	if before2 != nil {
		t.Error("expected nil for safe tool")
	}
}

func TestSession_Steering(t *testing.T) {
	session := NewSession(
		[]Message{TextMessage(RoleUser, "start")},
	)
	ctx := context.Background()

	// Queue steering before NextRequest
	session.Steer(TextMessage(RoleUser, "also consider X"))

	req, _ := session.NextRequest(ctx)
	if req == nil {
		t.Fatal("expected request")
	}

	// Steering message should be in the messages now
	msgs := session.Messages()
	found := false
	for _, m := range msgs {
		if m.Text() == "also consider X" {
			found = true
			break
		}
	}
	if !found {
		t.Error("steering message not found in history")
	}
}

func TestSession_FollowUp(t *testing.T) {
	session := NewSession(
		[]Message{TextMessage(RoleUser, "hello")},
	)
	ctx := context.Background()

	session.FollowUp(TextMessage(RoleUser, "one more thing"))

	// Get request and simulate a no-tool response
	session.NextRequest(ctx)
	session.HandleResponse(ctx, StreamResponse{
		Message: TextMessage(RoleAssistant, "hi"),
	})

	// ShouldContinue should drain follow-up and return true
	if !session.ShouldContinue(ctx) {
		t.Error("expected ShouldContinue true with pending follow-up")
	}

	// After draining, second call should be false
	session.AdvanceTurn(ctx)
	session.NextRequest(ctx)
	session.HandleResponse(ctx, StreamResponse{
		Message: TextMessage(RoleAssistant, "done"),
	})
	if session.ShouldContinue(ctx) {
		t.Error("expected ShouldContinue false with no more follow-ups")
	}
}

func TestSession_MaxTurns(t *testing.T) {
	session := NewSession(
		[]Message{TextMessage(RoleUser, "go")},
		WithSessionMaxTurns(2),
	)
	ctx := context.Background()

	// Turn 0
	req, _ := session.NextRequest(ctx)
	if req == nil {
		t.Fatal("expected request on turn 0")
	}
	session.HandleResponse(ctx, StreamResponse{
		Message: Message{Role: RoleAssistant, Content: []Content{
			{Type: ContentToolCalls, ToolCalls: []ToolCall{{ID: "c1", Name: "x"}}},
		}},
	})
	session.HandleToolResult(ctx, "c1", ToolResult{Content: "ok"})
	session.AdvanceTurn(ctx)

	// Turn 1
	req, _ = session.NextRequest(ctx)
	if req == nil {
		t.Fatal("expected request on turn 1")
	}
	session.HandleResponse(ctx, StreamResponse{
		Message: Message{Role: RoleAssistant, Content: []Content{
			{Type: ContentToolCalls, ToolCalls: []ToolCall{{ID: "c2", Name: "x"}}},
		}},
	})
	session.HandleToolResult(ctx, "c2", ToolResult{Content: "ok"})
	session.AdvanceTurn(ctx)

	// Turn 2 — should exceed maxTurns
	req, _ = session.NextRequest(ctx)
	if req != nil {
		t.Error("expected nil request when maxTurns exceeded")
	}
}
