package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// ConfigHasher provides deterministic hashing for config structs.
// Used to deduplicate agent/flow versions by content.
type ConfigHasher struct {
	data map[string]any
}

// NewConfigHasher creates a new hasher instance.
func NewConfigHasher() *ConfigHasher {
	return &ConfigHasher{
		data: make(map[string]any),
	}
}

// Add includes a key-value pair in the hash computation.
// Values are JSON-serialized for consistent representation.
func (h *ConfigHasher) Add(key string, value any) *ConfigHasher {
	if value == nil {
		return h
	}
	h.data[key] = value
	return h
}

// Hash computes the SHA256 hash of the config data.
// Returns the first 16 hex characters for readability.
func (h *ConfigHasher) Hash() string {
	if len(h.data) == 0 {
		return ""
	}

	// Sort keys for deterministic ordering
	keys := make([]string, 0, len(h.data))
	for k := range h.data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build ordered map for JSON serialization
	ordered := make([]any, 0, len(keys)*2)
	for _, k := range keys {
		ordered = append(ordered, k, h.data[k])
	}

	// Serialize to JSON (canonical form)
	jsonBytes, err := json.Marshal(ordered)
	if err != nil {
		// Fallback: use raw string representation
		jsonBytes = []byte("")
		for _, k := range keys {
			v, _ := json.Marshal(h.data[k])
			jsonBytes = append(jsonBytes, []byte(k)...)
			jsonBytes = append(jsonBytes, v...)
		}
	}

	// Compute SHA256 and return first 16 chars
	hash := sha256.Sum256(jsonBytes)
	return hex.EncodeToString(hash[:])[:16]
}

// QuickHash is a convenience function for hashing a single struct.
func QuickHash(v any) string {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(jsonBytes)
	return hex.EncodeToString(hash[:])[:16]
}
