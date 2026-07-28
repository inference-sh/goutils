package deepmap

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestWalk(t *testing.T) {
	for _, tt := range WalkTestCases {
		t.Run(tt.Name, func(t *testing.T) {
			input := deepCopy(tt.Input)
			iter := Walk(input)
			iter(tt.Modifier)

			if !reflect.DeepEqual(input, tt.Want) {
				t.Errorf("Walk() = %v, want %v", input, tt.Want)
			}
		})
	}
}

func TestPath(t *testing.T) {
	input := deepCopy(nestedStructure)
	var paths [][]Element
	iter := Walk(input)
	iter(func(n *Visitor) Response {
		if n.Kind == KindScalar {
			paths = append(paths, n.Path)
		}
		return Keep()
	})

	// Verify paths for scalar values
	expectedPaths := [][]Element{
		{
			{Key: "user", IsMap: true},
			{Key: "details", IsMap: true},
			{Key: "name", IsMap: true},
		},
		{
			{Key: "user", IsMap: true},
			{Key: "details", IsMap: true},
			{Key: "contacts", IsMap: true},
			{Index: 0},
		},
		{
			{Key: "user", IsMap: true},
			{Key: "details", IsMap: true},
			{Key: "contacts", IsMap: true},
			{Index: 1},
		},
	}

	// Sort both slices since map iteration order is not guaranteed
	sortPaths := func(p [][]Element) {
		sort.Slice(p, func(i, j int) bool {
			return pathToString(p[i]) < pathToString(p[j])
		})
	}
	sortPaths(paths)
	sortPaths(expectedPaths)

	if !reflect.DeepEqual(paths, expectedPaths) {
		t.Errorf("Path tracking failed.\nGot: %v\nWant: %v", paths, expectedPaths)
	}
}

func TestReplace(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		modifier func(*Visitor) Response
		want     any
	}{
		{
			name: "replace in map",
			input: map[string]any{
				"key": "old value",
			},
			modifier: func(n *Visitor) Response {
				if n.Key == "key" {
					return Replace("new value")
				}
				return Keep()
			},
			want: map[string]any{
				"key": "new value",
			},
		},
		{
			name:  "replace in array",
			input: []any{"first", "second", "third"},
			modifier: func(n *Visitor) Response {
				if str, ok := n.Value.(string); ok && str == "second" {
					return Replace("replaced")
				}
				return Keep()
			},
			want: []any{"first", "replaced", "third"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iter := Walk(tt.input)
			iter(tt.modifier)

			if !reflect.DeepEqual(tt.input, tt.want) {
				t.Errorf("Replace() result = %v, want %v", tt.input, tt.want)
			}
		})
	}
}

func TestDeepNestedReplace(t *testing.T) {
	// Complex nested structure: object -> array -> object -> array -> object
	input := map[string]any{
		"level1": map[string]any{
			"data": []any{
				map[string]any{
					"nested": []any{
						map[string]any{
							"deepValue": "original",
							"siblings": []any{
								"keep1",
								"toReplace",
								"keep2",
							},
						},
					},
				},
			},
		},
		"level1Sibling": map[string]any{
			"arrays": []any{
				[]any{
					map[string]any{
						"value": "target",
					},
				},
			},
		},
	}

	tests := []struct {
		name     string
		path     []string
		oldValue string
		newValue string
		want     string
	}{
		{
			name:     "replace deep object value",
			oldValue: "original",
			newValue: "modified",
		},
		{
			name:     "replace in deep array",
			oldValue: "toReplace",
			newValue: "replaced",
		},
		{
			name:     "replace in nested array of arrays",
			oldValue: "target",
			newValue: "hit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := false
			iter := Walk(input)
			iter(func(n *Visitor) Response {
				if str, ok := n.Value.(string); ok && str == tt.oldValue {
					found = true
					return Replace(tt.newValue)
				}
				return Keep()
			})

			if !found {
				t.Errorf("Value %s not found in structure", tt.oldValue)
			}

			// Verify the changes
			iter = Walk(input)
			iter(func(n *Visitor) Response {
				if str, ok := n.Value.(string); ok {
					if str == tt.oldValue {
						t.Errorf("Found old value %s that should have been replaced", tt.oldValue)
					}
					if str == tt.newValue {
						found = true
					}
				}
				return Keep()
			})

			if !found {
				t.Errorf("New value %s not found in structure", tt.newValue)
			}
		})
	}
}

func TestReplaceObjectDuringIteration(t *testing.T) {
	input := deepCopy(replacementData)

	var parentSeen bool
	var oldChildrenSeen bool
	var newChildrenCount int

	iter := Walk(input)
	iter(func(n *Visitor) Response {
		if n.Key == "obj" {
			parentSeen = true
			// Replace with new object
			newObj := map[string]any{
				"new1": "newvalue1",
				"new2": "newvalue2",
			}
			return Replace(newObj)
		}
		if n.Key == "old1" || n.Key == "old2" {
			if !parentSeen {
				t.Error("Saw child before parent")
			}
			oldChildrenSeen = true
		}
		if n.Key == "new1" || n.Key == "new2" {
			if !parentSeen {
				t.Error("Saw new child before parent")
			}
			newChildrenCount++
		}
		return Keep()
	})

	// Verify we never saw old children
	if oldChildrenSeen {
		t.Error("Should not have seen old children after parent replacement")
	}

	// Verify we saw both new children
	if newChildrenCount != 2 {
		t.Errorf("Expected to see 2 new children, got %d", newChildrenCount)
	}
}

func TestStopBranch(t *testing.T) {
	input := deepCopy(branchStopData)

	var sawC, sawD bool
	var sawE bool
	var sawF bool

	iter := Walk(input)
	iter(func(n *Visitor) Response {
		// When we hit "b", verify we saw parent "a" and stop traversal
		if n.Key == "b" {
			if len(n.Path) == 0 || n.Path[0].Key != "a" {
				t.Error("Expected to see parent 'a' before 'b'")
			}
			return Keep().WithStopBranch()
		}

		// Track if we see c or d (we shouldn't)
		if n.Key == "c" || n.Key == "d" {
			sawC = true
			sawD = true
		}

		// We should still see sibling "e"
		if n.Key == "e" {
			if len(n.Path) == 0 || n.Path[0].Key != "a" {
				t.Error("Expected to see parent 'a' before 'e'")
			}
			sawE = true
		}

		// When we hit "f", replace and stop
		if n.Key == "f" {
			sawF = true
			newVal := map[string]any{"g": 5, "h": 6}
			return Replace(newVal).WithStopBranch()
		}

		// We should never see g or h
		if n.Key == "g" || n.Key == "h" {
			t.Error("Should not traverse replaced node after StopBranch")
		}

		return Keep()
	})

	// Verify expectations
	if sawC || sawD {
		t.Error("Should not have seen c or d after StopBranch on b")
	}
	if !sawE {
		t.Error("Should have seen sibling e even after StopBranch on b")
	}
	if !sawF {
		t.Error("Should have seen f")
	}

	// Verify final structure
	expected := map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"c": 1,
				"d": 2,
			},
			"e": 3,
		},
		"f": map[string]any{
			"g": 5,
			"h": 6,
		},
	}

	if !reflect.DeepEqual(input, expected) {
		t.Errorf("Final structure = %v, want %v", input, expected)
	}
}

func TestKeepVsNil(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		modifier func(*Visitor) Response
		want     any
	}{
		{
			name: "keep vs nil in map",
			input: map[string]any{
				"keep":    "value1",
				"setNil":  "value2",
				"replace": "value3",
			},
			modifier: func(n *Visitor) Response {
				switch n.Key {
				case "keep":
					return Keep()
				case "setNil":
					return Replace(nil)
				case "replace":
					return Replace("newValue")
				default:
					return Keep()
				}
			},
			want: map[string]any{
				"keep":    "value1",
				"setNil":  nil,
				"replace": "newValue",
			},
		},
		{
			name:  "keep vs nil in array",
			input: []any{"keep", "setNil", "replace"},
			modifier: func(n *Visitor) Response {
				if str, ok := n.Value.(string); ok {
					switch str {
					case "keep":
						return Keep()
					case "setNil":
						return Replace(nil)
					case "replace":
						return Replace("newValue")
					}
				}
				return Keep()
			},
			want: []any{"keep", nil, "newValue"},
		},
		{
			name: "keep with nested structures",
			input: map[string]any{
				"obj": map[string]any{
					"keep":    1,
					"setNil":  2,
					"replace": 3,
				},
				"arr": []any{
					map[string]any{"value": "keep"},
					map[string]any{"value": "setNil"},
					map[string]any{"value": "replace"},
				},
			},
			modifier: func(n *Visitor) Response {
				if n.Key == "value" {
					str, ok := n.Value.(string)
					if !ok {
						return Keep()
					}
					switch str {
					case "keep":
						return Keep()
					case "setNil":
						return Replace(nil)
					case "replace":
						return Replace("newValue")
					}
				}
				return Keep()
			},
			want: map[string]any{
				"obj": map[string]any{
					"keep":    1,
					"setNil":  2,
					"replace": 3,
				},
				"arr": []any{
					map[string]any{"value": "keep"},
					map[string]any{"value": nil},
					map[string]any{"value": "newValue"},
				},
			},
		},
		{
			name: "keep with stopBranch",
			input: map[string]any{
				"parent": map[string]any{
					"stopHere": map[string]any{
						"child1": "value1",
						"child2": "value2",
					},
					"setNil": "value3",
				},
			},
			modifier: func(n *Visitor) Response {
				switch n.Key {
				case "stopHere":
					return Keep().WithStopBranch()
				case "setNil":
					return Replace(nil)
				default:
					return Keep()
				}
			},
			want: map[string]any{
				"parent": map[string]any{
					"stopHere": map[string]any{
						"child1": "value1",
						"child2": "value2",
					},
					"setNil": nil,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := deepCopy(tt.input)
			iter := Walk(input)
			iter(tt.modifier)

			if !reflect.DeepEqual(input, tt.want) {
				t.Errorf("Walk() with Keep = %v, want %v", input, tt.want)
			}
		})
	}
}

func TestArrayObjectReplaceWithStopBranch(t *testing.T) {
	input := []any{
		map[string]any{
			"id": 1,
			"nested": map[string]any{
				"value": "keep",
			},
		},
		map[string]any{
			"id": 2,
			"nested": map[string]any{
				"value": "replace",
			},
		},
		map[string]any{
			"id": 3,
			"nested": map[string]any{
				"value": "keep",
			},
		},
	}

	var sawNestedAfterReplace bool
	var replacementVisited bool

	iter := Walk(input)
	iter(func(n *Visitor) Response {
		// Find the object with id 2 and replace it
		if m, ok := n.Value.(map[string]any); ok {
			if id, ok := m["id"].(int); ok && id == 2 {
				replacementObj := map[string]any{
					"id":       2,
					"newValue": "replaced",
					"deep": map[string]any{
						"shouldNotSee": true,
					},
				}
				return Replace(replacementObj).WithStopBranch()
			}
		}

		// Track if we see the nested value after replacement
		if str, ok := n.Value.(string); ok && str == "replace" {
			sawNestedAfterReplace = true
		}

		// Track if we visit the replacement object's internals
		if _, ok := n.Value.(bool); ok {
			replacementVisited = true
		}

		return Keep()
	})

	// Verify we didn't traverse into the replaced object
	if sawNestedAfterReplace {
		t.Error("Should not have seen nested 'replace' value after replacement")
	}
	if replacementVisited {
		t.Error("Should not have visited the replacement object's internals")
	}

	// Verify the structure is correct
	expected := []any{
		map[string]any{
			"id": 1,
			"nested": map[string]any{
				"value": "keep",
			},
		},
		map[string]any{
			"id":       2,
			"newValue": "replaced",
			"deep": map[string]any{
				"shouldNotSee": true,
			},
		},
		map[string]any{
			"id": 3,
			"nested": map[string]any{
				"value": "keep",
			},
		},
	}

	if !reflect.DeepEqual(input, expected) {
		t.Errorf("Final structure = %v, want %v", input, expected)
	}
}

// deepCopy creates a deep copy of a map/slice structure
func deepCopy(v any) any {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case map[string]any:
		newMap := make(map[string]any, len(val))
		for k, v := range val {
			newMap[k] = deepCopy(v)
		}
		return newMap
	case []any:
		newSlice := make([]any, len(val))
		for i, v := range val {
			newSlice[i] = deepCopy(v)
		}
		return newSlice
	default:
		return v // For scalar values, just return as is
	}
}

// pathToString converts a path to a string for sorting
func pathToString(path []Element) string {
	var parts []string
	for _, e := range path {
		if e.IsMap {
			parts = append(parts, e.Key)
		} else {
			parts = append(parts, fmt.Sprintf("[%d]", e.Index))
		}
	}
	return strings.Join(parts, ".")
}
