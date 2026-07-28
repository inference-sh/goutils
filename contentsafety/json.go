package contentsafety

import (
	"bytes"
	"encoding/json"

	"github.com/inference-sh/goutils/deepmap"
)

// CleanJSON applies Clean to the string values inside a JSON document and
// re-serializes it.
//
// This is the only safe way to redact JSON. Running the patterns over the
// serialized bytes lets a match span a string boundary and consume the closing
// quote, turning `"url":"…?key=abc","next":1` into `"url":"…?[REDACTED],"next":1`
// — valid-looking, unparseable, and silent. Walking decoded values means no
// pattern ever sees a delimiter.
//
// Fields classified as metadata are skipped, so ids, URIs, hashes, and cursors
// survive intact for programs consuming the output.
//
// The input is not modified: decoding produces a fresh tree for deepmap to
// rewrite in place.
func CleanJSON(raw json.RawMessage, sets RuleSet) (json.RawMessage, []Finding) {
	return transformJSON(raw, func(path []string, key, value string) (string, []Finding) {
		if ClassifyKey(path, key) == ClassMetadata {
			return value, nil
		}
		return Clean(value, sets)
	})
}

// transformJSON decodes raw, applies fn to every string value with its path and
// key, and re-encodes. Returns the input unchanged if it is not valid JSON, so
// a caller handling mixed payloads does not have to pre-check.
func transformJSON(
	raw json.RawMessage,
	fn func(path []string, key, value string) (string, []Finding),
) (json.RawMessage, []Finding) {
	if len(raw) == 0 {
		return raw, nil
	}

	// UseNumber keeps large integers exact. Without it a 64-bit id round-trips
	// through float64 and comes back mangled — a silent data corruption that
	// only shows up on big values.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var tree any
	if err := dec.Decode(&tree); err != nil {
		return raw, nil
	}

	var findings []Finding
	iter := deepmap.Walk(tree)
	iter(func(n *deepmap.Visitor) deepmap.Response {
		s, ok := n.Value.(string)
		if !ok {
			return deepmap.Keep()
		}
		cleaned, found := fn(pathKeys(n.Path), n.Key, s)
		findings = append(findings, found...)
		if cleaned == s {
			return deepmap.Keep()
		}
		return deepmap.Replace(cleaned)
	})

	// deepmap rewrites containers in place but cannot replace a root scalar,
	// which has no parent to write through to.
	if s, ok := tree.(string); ok {
		if cleaned, found := fn(nil, "", s); cleaned != s {
			findings = append(findings, found...)
			tree = cleaned
		}
	}

	out, err := json.Marshal(tree)
	if err != nil {
		return raw, findings
	}
	return out, findings
}

// pathKeys reduces a deepmap path to its map keys. Array indices carry no
// classification signal — an element inherits the key of the array holding it.
func pathKeys(path []deepmap.Element) []string {
	keys := make([]string, 0, len(path))
	for _, e := range path {
		if e.IsMap && e.Key != "" {
			keys = append(keys, e.Key)
		}
	}
	return keys
}
