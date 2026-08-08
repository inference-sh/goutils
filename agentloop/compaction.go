package agentloop

import (
	"context"
	"strings"
	"unicode/utf8"
)

// Meta keys written by the compaction system.
const (
	MetaKeyCompaction     = "agentloop.compaction"
	MetaKeyCompactedCount = "agentloop.compacted_count"
)

// CompactionConfig controls when and how the loop compacts context.
type CompactionConfig struct {
	// MaxTokens is the context budget. Compaction triggers when estimated
	// tokens exceed this.
	MaxTokens int

	// KeepRecentTokens is the number of recent tokens to preserve in the
	// tail after compaction. Defaults to 25% of MaxTokens if zero.
	KeepRecentTokens int

	// SummarizeFn generates an LLM-produced summary of the compacted
	// messages. If nil, the loop falls back to extractive summarization.
	SummarizeFn func(ctx context.Context, messages []Message) (string, error)
}

// CompactResult describes what happened during compaction.
type CompactResult struct {
	CompactedCount  int
	EstimatedTokens int
	Method          string // "extractive" or "llm"
	Summary         string
}

// AutoCompact checks whether the messages exceed the token budget and
// compacts if needed. Returns the (possibly shortened) messages and a
// result describing what happened. If no compaction was needed, result
// is nil.
func AutoCompact(ctx context.Context, messages []Message, cfg CompactionConfig) ([]Message, *CompactResult, error) {
	if cfg.MaxTokens <= 0 {
		return messages, nil, nil
	}

	estimated := EstimateContextTokens(messages)
	if estimated <= cfg.MaxTokens {
		return messages, nil, nil
	}

	keepRecent := cfg.KeepRecentTokens
	if keepRecent <= 0 {
		keepRecent = cfg.MaxTokens / 4
	}

	// Find the cut point: walk backward keeping ~keepRecent tokens in the tail
	cutIndex := findCutPoint(messages, keepRecent)
	if cutIndex <= 1 {
		return messages, nil, nil
	}

	toSummarize := messages[:cutIndex]
	tail := messages[cutIndex:]

	// Try LLM summarization first
	var summary string
	var method string
	if cfg.SummarizeFn != nil {
		llmSummary, err := cfg.SummarizeFn(ctx, toSummarize)
		if err == nil && llmSummary != "" {
			summary = llmSummary
			method = "llm"
		}
	}

	// Fall back to extractive
	if summary == "" {
		summary = extractiveSummary(toSummarize)
		method = "extractive"
	}

	// Build compacted messages: summary as system message + retained tail
	compacted := make([]Message, 0, 1+len(tail))
	compacted = append(compacted, Message{
		Role:    RoleSystem,
		Content: []Content{{Type: ContentText, Text: summary}},
		Meta:    map[string]any{MetaKeyCompaction: true, MetaKeyCompactedCount: cutIndex},
	})
	compacted = append(compacted, tail...)

	return compacted, &CompactResult{
		CompactedCount:  cutIndex,
		EstimatedTokens: EstimateContextTokens(compacted),
		Method:          method,
		Summary:         summary,
	}, nil
}

// findCutPoint walks messages backward, accumulating token estimates until
// keepTokens is reached. Returns the index that splits [compact | retain].
func findCutPoint(messages []Message, keepTokens int) int {
	tokens := 0
	for i := len(messages) - 1; i >= 0; i-- {
		tokens += EstimateMessageTokens(messages[i])
		if tokens >= keepTokens {
			return i
		}
	}
	return 0
}

// extractiveSummary builds a summary by pulling key content from user and
// assistant messages, truncating each to a reasonable length.
func extractiveSummary(messages []Message) string {
	const maxRunes = 200
	var b strings.Builder
	b.WriteString("## Conversation Summary (compacted)\n\n")

	found := false
	for _, m := range messages {
		if m.Role != RoleUser && m.Role != RoleAssistant {
			continue
		}
		text := m.Text()
		if text == "" {
			continue
		}
		if utf8.RuneCountInString(text) > maxRunes {
			text = string([]rune(text)[:maxRunes]) + "..."
		}
		if found {
			b.WriteByte('\n')
		}
		b.WriteByte('[')
		b.WriteString(string(m.Role))
		b.WriteString("] ")
		b.WriteString(text)
		found = true
	}

	if !found {
		return "Previous conversation context was compacted."
	}

	return b.String()
}
