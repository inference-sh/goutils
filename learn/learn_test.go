package learn

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldReview(t *testing.T) {
	assert.False(t, ShouldReview(0))
	assert.False(t, ShouldReview(9))
	assert.True(t, ShouldReview(10))
	assert.False(t, ShouldReview(11))
	assert.True(t, ShouldReview(20))
}

func TestExtractPrompt_wrapsConversation(t *testing.T) {
	p := ExtractPrompt("Agent: team/ops", "[user]: hi")
	assert.True(t, strings.HasPrefix(p, "Agent: team/ops\n\n"))
	assert.True(t, strings.HasSuffix(p, "\n[user]: hi\n</conversation>"))
	assert.True(t, strings.HasSuffix(strings.TrimSpace(ExtractTemplate()), "<conversation>"))
}

func TestDedupPrompt_fillsTemplate(t *testing.T) {
	p := DedupPrompt(Candidate{Type: "gotcha", Name: "nil-slice", Content: "body"},
		[]Existing{{Ref: "team/a", Description: "about a"}})
	assert.Contains(t, p, "nil-slice")
	assert.Contains(t, p, "- team/a: about a")
	assert.NotContains(t, p, "{{")
}

func TestParseCandidates_dropsIncomplete(t *testing.T) {
	got := ParseCandidates([]byte(`{"items":[{"type":"rule","name":"a","content":"b","trigger":"c"},{"name":"","content":"x"},{"name":"y"}]}`))
	require.Len(t, got, 1)
	assert.Equal(t, "a", got[0].Name)
	assert.Nil(t, ParseCandidates([]byte("not json")))
}

func TestParseDedup_defaultsToCreate(t *testing.T) {
	assert.Equal(t, DedupCreate, ParseDedup([]byte("garbage")).Action)
	assert.Equal(t, DedupCreate, ParseDedup([]byte(`{}`)).Action)
	a := ParseDedup([]byte(`{"action":"update","target":"t/x","content":"merged"}`))
	assert.Equal(t, DedupUpdate, a.Action)
	assert.Equal(t, "t/x", a.Target)
}

func TestSchemas_marshal(t *testing.T) {
	for _, s := range []map[string]any{CandidatesSchema(), DedupSchema()} {
		_, err := json.Marshal(s)
		require.NoError(t, err)
	}
}

func TestExtractInContext_isTheForkPromptWithoutTranscript(t *testing.T) {
	p := ExtractInContext()
	assert.Contains(t, p, "full conversation")
	assert.NotContains(t, p, "<conversation>")
	assert.NotContains(t, p, "belt skill use", "belt-only suggest-miss section stays in the CLI")
}
