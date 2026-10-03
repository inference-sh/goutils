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
	shown := []Existing{{Ref: "t/x"}}
	assert.Equal(t, DedupCreate, ParseDedup([]byte("garbage"), shown).Action)
	assert.Equal(t, DedupCreate, ParseDedup([]byte(`{}`), shown).Action)
	a := ParseDedup([]byte(`{"action":"update","target":"t/x","content":"merged"}`), shown)
	assert.Equal(t, DedupUpdate, a.Action)
	assert.Equal(t, "t/x", a.Target)
}

// The target is free text. Prose around a shown ref still names it; a target
// naming none of them makes the answer a create.
func TestParseDedup_updateTargetMustBeAShownRef(t *testing.T) {
	shown := []Existing{{Ref: "team/known"}, {Ref: "team/known-v2"}}
	cases := map[string]struct {
		target     string
		wantAction string
		wantTarget string
	}{
		"prose after the ref":            {"team/known as the merge target", DedupUpdate, "team/known"},
		"ref not first":                  {"update team/known-v2 (content below)", DedupUpdate, "team/known-v2"},
		"quoted":                         {`"team/known".`, DedupUpdate, "team/known"},
		"none shown":                     {"see below", DedupCreate, ""},
		"a longer name is another entry": {"team/known-but-different", DedupCreate, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`{"action":"update","target":"` + strings.ReplaceAll(tc.target, `"`, `\"`) + `","content":"merged"}`)
			a := ParseDedup(raw, shown)
			assert.Equal(t, tc.wantAction, a.Action)
			assert.Equal(t, tc.wantTarget, a.Target)
		})
	}
}

func TestDedupSchema_targetIsAnEnumOfTheShownRefs(t *testing.T) {
	props := DedupSchema([]Existing{{Ref: "a/b"}, {Ref: "c/d"}})["properties"].(map[string]any)
	assert.Equal(t, []any{"a/b", "c/d"}, props["target"].(map[string]any)["enum"])
	_, hasEnum := DedupSchema(nil)["properties"].(map[string]any)["target"].(map[string]any)["enum"]
	assert.False(t, hasEnum, "nothing shown: any string, since the answer can only be create")
}

func TestSchemas_marshal(t *testing.T) {
	for _, s := range []map[string]any{CandidatesSchema(), DedupSchema([]Existing{{Ref: "a/b"}})} {
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
