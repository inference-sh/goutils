package agentloop

import (
	"context"
	"strings"
	"testing"
)

func TestEstimateTokens(t *testing.T) {
	tests := []struct {
		text     string
		expected int
	}{
		{"", 0},
		{"hi", 0},
		{"hello world", 2},
		{strings.Repeat("a", 100), 25},
	}
	for _, tt := range tests {
		got := EstimateTokens(tt.text)
		if got != tt.expected {
			t.Errorf("EstimateTokens(%q) = %d, want %d", tt.text, got, tt.expected)
		}
	}
}

func TestEstimateContextTokens(t *testing.T) {
	msgs := []Message{
		TextMessage(RoleUser, "hello world"),
		TextMessage(RoleAssistant, "hi there"),
	}
	tokens := EstimateContextTokens(msgs)
	if tokens <= 0 {
		t.Error("expected positive token count")
	}
}

func TestAutoCompact_NoCompactionNeeded(t *testing.T) {
	msgs := []Message{
		TextMessage(RoleUser, "hi"),
		TextMessage(RoleAssistant, "hello"),
	}
	result, cr, err := AutoCompact(context.Background(), msgs, CompactionConfig{MaxTokens: 10000})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr != nil {
		t.Error("expected no compaction")
	}
	if len(result) != 2 {
		t.Errorf("expected 2 messages, got %d", len(result))
	}
}

func TestAutoCompact_ZeroBudget(t *testing.T) {
	msgs := []Message{TextMessage(RoleUser, "hi")}
	result, cr, err := AutoCompact(context.Background(), msgs, CompactionConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr != nil {
		t.Error("expected no compaction with zero budget")
	}
	if len(result) != 1 {
		t.Errorf("expected 1 message, got %d", len(result))
	}
}

func TestAutoCompact_Extractive(t *testing.T) {
	// Create enough messages to exceed a small budget
	var msgs []Message
	for i := 0; i < 20; i++ {
		msgs = append(msgs,
			TextMessage(RoleUser, strings.Repeat("question ", 50)),
			TextMessage(RoleAssistant, strings.Repeat("answer ", 50)),
		)
	}

	result, cr, err := AutoCompact(context.Background(), msgs, CompactionConfig{
		MaxTokens:        100,
		KeepRecentTokens: 50,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr == nil {
		t.Fatal("expected compaction to occur")
	}
	if cr.Method != "extractive" {
		t.Errorf("expected extractive method, got %s", cr.Method)
	}
	if cr.CompactedCount <= 0 {
		t.Error("expected positive compacted count")
	}
	if len(result) < 2 {
		t.Error("expected at least summary + one retained message")
	}

	// First message should be the compaction summary
	if result[0].Role != RoleSystem {
		t.Errorf("expected system role for summary, got %s", result[0].Role)
	}
	if result[0].Meta[MetaKeyCompaction] != true {
		t.Error("expected compaction meta flag")
	}
}

func TestAutoCompact_LLMSummarization(t *testing.T) {
	var msgs []Message
	for i := 0; i < 20; i++ {
		msgs = append(msgs,
			TextMessage(RoleUser, strings.Repeat("q ", 50)),
			TextMessage(RoleAssistant, strings.Repeat("a ", 50)),
		)
	}

	summarizeCalled := false
	result, cr, err := AutoCompact(context.Background(), msgs, CompactionConfig{
		MaxTokens:        100,
		KeepRecentTokens: 50,
		SummarizeFn: func(ctx context.Context, messages []Message) (string, error) {
			summarizeCalled = true
			return "LLM summary of conversation", nil
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !summarizeCalled {
		t.Error("expected LLM summarize to be called")
	}
	if cr.Method != "llm" {
		t.Errorf("expected llm method, got %s", cr.Method)
	}
	if !strings.Contains(result[0].Text(), "LLM summary") {
		t.Errorf("expected LLM summary in first message, got %q", result[0].Text())
	}
}

func TestAutoCompact_LLMFallbackToExtractive(t *testing.T) {
	var msgs []Message
	for i := 0; i < 20; i++ {
		msgs = append(msgs,
			TextMessage(RoleUser, strings.Repeat("q ", 50)),
			TextMessage(RoleAssistant, strings.Repeat("a ", 50)),
		)
	}

	_, cr, err := AutoCompact(context.Background(), msgs, CompactionConfig{
		MaxTokens:        100,
		KeepRecentTokens: 50,
		SummarizeFn: func(ctx context.Context, messages []Message) (string, error) {
			return "", nil // empty = fallback
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Method != "extractive" {
		t.Errorf("expected extractive fallback, got %s", cr.Method)
	}
}

func TestFindCutPoint(t *testing.T) {
	msgs := []Message{
		TextMessage(RoleUser, "first"),
		TextMessage(RoleAssistant, "second"),
		TextMessage(RoleUser, "third"),
		TextMessage(RoleAssistant, "fourth"),
	}

	// Keep enough tokens for the last message
	lastTokens := EstimateMessageTokens(msgs[3])
	cut := findCutPoint(msgs, lastTokens)
	if cut < 2 {
		t.Errorf("expected cut at index 2+, got %d", cut)
	}

	// Keep everything
	allTokens := EstimateContextTokens(msgs)
	cut = findCutPoint(msgs, allTokens+100)
	if cut != 0 {
		t.Errorf("expected cut at 0 when keeping all, got %d", cut)
	}
}
