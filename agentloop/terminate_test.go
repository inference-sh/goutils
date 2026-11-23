package agentloop

import (
	"context"
	"testing"
)

// BeforeToolCallResult.Terminate and AfterToolCallResult.Terminate were
// documented but never read, so a hook could not stop the loop
// (aikido 796589952).

func twoCallsThenText() StreamFn {
	return mockStreamFn(
		toolCallResponse(
			ToolCall{ID: "c1", Name: "a"},
			ToolCall{ID: "c2", Name: "b"},
		),
		toolCallResponse(ToolCall{ID: "c3", Name: "after-stop"}),
		textResponse("done"),
	)
}

func runTerminate(t *testing.T, mode ToolExecutionMode, hooks Hooks) []string {
	t.Helper()
	var executed []string
	exec := func(ctx context.Context, call ToolCall) (ToolResult, error) {
		executed = append(executed, call.Name)
		return ToolResult{Content: "ok"}, nil
	}
	if mode == ToolExecParallel {
		// Parallel calls append concurrently; serialise through a channel.
		ch := make(chan string, 16)
		exec = func(ctx context.Context, call ToolCall) (ToolResult, error) {
			ch <- call.Name
			return ToolResult{Content: "ok"}, nil
		}
		defer func() {
			close(ch)
		}()
		loop := New(twoCallsThenText(), exec, WithHooks(hooks), WithToolExecution(mode))
		if _, err := loop.Run(context.Background(), []Message{TextMessage(RoleUser, "go")}); err != nil {
			t.Fatalf("run: %v", err)
		}
		for len(ch) > 0 {
			executed = append(executed, <-ch)
		}
		return executed
	}
	loop := New(twoCallsThenText(), exec, WithHooks(hooks), WithToolExecution(mode))
	if _, err := loop.Run(context.Background(), []Message{TextMessage(RoleUser, "go")}); err != nil {
		t.Fatalf("run: %v", err)
	}
	return executed
}

func ranAfterStop(executed []string) bool {
	for _, n := range executed {
		if n == "after-stop" {
			return true
		}
	}
	return false
}

func TestTerminate_BeforeAllCallsStopsAfterBatch(t *testing.T) {
	for _, mode := range []ToolExecutionMode{ToolExecSequential, ToolExecParallel} {
		hooks := Hooks{BeforeToolCall: func(ctx context.Context, c BeforeToolCallContext) (*BeforeToolCallResult, error) {
			return &BeforeToolCallResult{Terminate: true}, nil
		}}
		got := runTerminate(t, mode, hooks)
		if len(got) != 2 || ranAfterStop(got) {
			t.Errorf("mode %d: executed %v, want only the first batch", mode, got)
		}
	}
}

func TestTerminate_BeforeSomeCallsDoesNotStop(t *testing.T) {
	for _, mode := range []ToolExecutionMode{ToolExecSequential, ToolExecParallel} {
		hooks := Hooks{BeforeToolCall: func(ctx context.Context, c BeforeToolCallContext) (*BeforeToolCallResult, error) {
			return &BeforeToolCallResult{Terminate: c.Call.ID == "c1"}, nil
		}}
		if got := runTerminate(t, mode, hooks); !ranAfterStop(got) {
			t.Errorf("mode %d: executed %v, want the loop to continue", mode, got)
		}
	}
}

func TestTerminate_AfterAnyCallStopsAfterBatch(t *testing.T) {
	for _, mode := range []ToolExecutionMode{ToolExecSequential, ToolExecParallel} {
		hooks := Hooks{AfterToolCall: func(ctx context.Context, c AfterToolCallContext) (*AfterToolCallResult, error) {
			return &AfterToolCallResult{Terminate: c.Call.ID == "c2"}, nil
		}}
		got := runTerminate(t, mode, hooks)
		if len(got) != 2 || ranAfterStop(got) {
			t.Errorf("mode %d: executed %v, want only the first batch", mode, got)
		}
	}
}

func TestTerminate_ResetsEachTurn(t *testing.T) {
	// Terminate in turn 0 only for a batch that is not unanimous, then a
	// follow-up batch with none: the stale flags must not stop turn 1.
	s := NewSession(nil, WithSessionHooks(Hooks{
		BeforeToolCall: func(ctx context.Context, c BeforeToolCallContext) (*BeforeToolCallResult, error) {
			return &BeforeToolCallResult{Terminate: c.Call.ID == "x1"}, nil
		},
	}))
	ctx := context.Background()
	s.HandleResponse(ctx, toolCallResponse(ToolCall{ID: "x1"}))
	_, _ = s.BeforeToolCall(ctx, ToolCall{ID: "x1"})
	_, _ = s.HandleToolResult(ctx, "x1", ToolResult{})
	if s.ShouldContinue(ctx) {
		t.Fatal("a unanimous Before terminate must stop")
	}
	_ = s.AdvanceTurn(ctx)
	s.HandleResponse(ctx, toolCallResponse(ToolCall{ID: "y1"}))
	_, _ = s.BeforeToolCall(ctx, ToolCall{ID: "y1"})
	_, _ = s.HandleToolResult(ctx, "y1", ToolResult{})
	if !s.ShouldContinue(ctx) {
		t.Fatal("terminate from an earlier turn leaked into this one")
	}
}
