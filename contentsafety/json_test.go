package contentsafety

import (
	"encoding/json"
	"strings"
	"testing"
)

// The failure this whole path exists to prevent: raw regex over serialized JSON
// consumes the closing quote and produces a document that no longer parses.
func TestCleanJSON_outputStaysParseable(t *testing.T) {
	in := `{"body":"key is 1nfsh-01j8x2k4m5n6p7q8r9s0t1v2w3","next":1}`

	out, findings := CleanJSON(json.RawMessage(in), Credentials)

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "1nfsh-01j8") {
		t.Errorf("credential survived: %s", out)
	}
	if got["next"] != float64(1) {
		t.Errorf("sibling key was disturbed: %v", got["next"])
	}
	if len(findings) == 0 {
		t.Error("expected a finding")
	}
}

func TestCleanJSON_leavesMetadataFieldsIntact(t *testing.T) {
	// An id shaped exactly like a credential must survive: programs index on it.
	in := `{"id":"1nfsh-01j8x2k4m5n6p7q8r9s0t1v2w3","description":"key 1nfsh-01j8x2k4m5n6p7q8r9s0t1v2w3"}`

	out, _ := CleanJSON(json.RawMessage(in), Credentials)

	var got map[string]string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got["id"] != "1nfsh-01j8x2k4m5n6p7q8r9s0t1v2w3" {
		t.Errorf("metadata field was rewritten: %q", got["id"])
	}
	if strings.Contains(got["description"], "1nfsh-01j8") {
		t.Errorf("content field was not cleaned: %q", got["description"])
	}
}

func TestCleanJSON_reachesNestedAndArrayValues(t *testing.T) {
	in := `{"results":[{"text":"<|im_start|>evil"},{"text":"fine"}],"meta":{"note":"<|im_end|>"}}`

	out, _ := CleanJSON(json.RawMessage(in), SpecialTokens)

	if strings.Contains(string(out), "<|im_start|>") || strings.Contains(string(out), "<|im_end|>") {
		t.Errorf("nested or array value not cleaned: %s", out)
	}
	if !strings.Contains(string(out), "fine") {
		t.Errorf("untouched sibling was lost: %s", out)
	}
}

// Without UseNumber a large id round-trips through float64 and comes back
// changed — silent corruption that only appears on big values.
func TestCleanJSON_preservesLargeIntegersExactly(t *testing.T) {
	in := `{"id":9007199254740993,"description":"hello"}`

	out, _ := CleanJSON(json.RawMessage(in), Credentials)

	if !strings.Contains(string(out), "9007199254740993") {
		t.Errorf("large integer was mangled: %s", out)
	}
}

func TestCleanJSON_invalidJSONReturnedUnchanged(t *testing.T) {
	in := json.RawMessage("not json at all")

	out, findings := CleanJSON(in, AllRules)

	if string(out) != string(in) {
		t.Errorf("non-JSON input was altered: %s", out)
	}
	if len(findings) != 0 {
		t.Errorf("unexpected findings: %v", findings)
	}
}

func TestCleanJSON_emptyInput(t *testing.T) {
	if out, _ := CleanJSON(nil, AllRules); len(out) != 0 {
		t.Errorf("expected empty output, got %s", out)
	}
}

func TestClassifyKey(t *testing.T) {
	cases := []struct {
		path []string
		key  string
		want KeyClass
	}{
		{nil, "id", ClassMetadata},
		{nil, "short_id", ClassMetadata},
		{nil, "created_at", ClassMetadata},
		{nil, "uri", ClassMetadata},
		{nil, "next_page_token", ClassMetadata},
		{nil, "description", ClassContent},
		{nil, "instructions", ClassContent},
		{nil, "body", ClassContent},
		// unknown keys default to content: under-marking is silent, over-marking is visible
		{nil, "some_new_field", ClassContent},
		// anything inside a content container is content whatever it is called
		{[]string{"messages"}, "arbitrary", ClassContent},
	}
	for _, tc := range cases {
		if got := ClassifyKey(tc.path, tc.key); got != tc.want {
			t.Errorf("ClassifyKey(%v, %q) = %v, want %v", tc.path, tc.key, got, tc.want)
		}
	}
}

// The same field arrives as created_at, createdAt, or CreatedAt depending on
// whether it came from belt, a Go struct, or a third-party MCP server.
func TestClassifyKey_normalizesKeySpelling(t *testing.T) {
	for _, spelling := range []string{"created_at", "createdAt", "CreatedAt", "created-at"} {
		if got := ClassifyKey(nil, spelling); got != ClassMetadata {
			t.Errorf("ClassifyKey(%q) = %v, want ClassMetadata", spelling, got)
		}
	}
}
