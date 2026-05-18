package jsonutil

import jsoniter "github.com/json-iterator/go"

// JSON provides a global json instance that's compatible with the standard library
var JSON = jsoniter.ConfigCompatibleWithStandardLibrary

func JSONMarshal(v any) ([]byte, error) {
	return JSON.Marshal(v)
}

func JSONUnmarshal(data []byte, v any) error {
	return JSON.Unmarshal(data, v)
}

func JSONMarshalIndent(v any, prefix, indent string) ([]byte, error) {
	return JSON.MarshalIndent(v, prefix, indent)
}

func JSONFilterFields(item any, fields []string) ([]byte, error) {
	if len(fields) == 0 {
		return nil, nil
	}

	fullJSON, err := JSONMarshal(item)
	if err != nil {
		return nil, err
	}

	var fullData map[string]any
	if err := JSONUnmarshal(fullJSON, &fullData); err != nil {
		return nil, err
	}

	filtered := make(map[string]any, len(fields))
	for _, field := range fields {
		if val, exists := fullData[field]; exists {
			filtered[field] = val
		}
	}
	return JSONMarshal(filtered)
}
