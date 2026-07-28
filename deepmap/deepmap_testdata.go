package deepmap

// Test data structures used across different tests
var (
	simpleMap = map[string]any{
		"name": "John",
		"age":  30,
	}

	simpleMapModified = map[string]any{
		"name": "Jane",
		"age":  30,
	}

	nestedStructure = map[string]any{
		"user": map[string]any{
			"details": map[string]any{
				"name": "John",
				"contacts": []any{
					"email@example.com",
					"phone@example.com",
				},
			},
		},
	}

	nestedStructureModified = map[string]any{
		"user": map[string]any{
			"details": map[string]any{
				"name": "Jane",
				"contacts": []any{
					"email@example.com",
					"phone@example.com",
					"new@example.com",
				},
			},
		},
	}

	arrayData = []any{
		"first",
		"second",
		"third",
	}

	arrayDataModified = []any{
		"first",
		"modified",
		"third",
	}

	branchStopData = map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"c": 1,
				"d": 2,
			},
			"e": 3,
		},
		"f": 4,
	}

	replacementData = map[string]any{
		"obj": map[string]any{
			"old1": "value1",
			"old2": "value2",
		},
	}
)

// WalkTestCase represents a test case for the Walk function
type WalkTestCase struct {
	Name     string
	Input    any
	Modifier func(*Visitor) Response
	Want     any
}

// WalkTestCases contains all test cases for the Walk function
var WalkTestCases = []WalkTestCase{
	{
		Name:  "simple_map_modification",
		Input: simpleMap,
		Modifier: func(n *Visitor) Response {
			if n.Kind == KindScalar && n.Key == "name" {
				return Replace("Jane")
			}
			return Keep()
		},
		Want: simpleMapModified,
	},
	{
		Name:  "nested_structure_traversal",
		Input: nestedStructure,
		Modifier: func(n *Visitor) Response {
			if n.Kind == KindScalar && n.Key == "name" {
				return Replace("Jane")
			}
			if n.Kind == KindArray && n.Key == "contacts" {
				if arr, ok := n.Value.([]any); ok {
					return Replace(append(arr, "new@example.com"))
				}
			}
			return Keep()
		},
		Want: nestedStructureModified,
	},
	{
		Name:  "nil_input",
		Input: nil,
		Modifier: func(n *Visitor) Response {
			return Keep()
		},
		Want: nil,
	},
	{
		Name:  "array_modification",
		Input: arrayData,
		Modifier: func(n *Visitor) Response {
			if n.Kind == KindScalar {
				if str, ok := n.Value.(string); ok && str == "second" {
					return Replace("modified")
				}
			}
			return Keep()
		},
		Want: arrayDataModified,
	},
}
