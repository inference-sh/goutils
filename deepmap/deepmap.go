// Package deepmap walks nested map/slice structures, letting a visitor inspect
// each value with its key and full path and optionally replace it.
//
// It is shaped for data decoded from JSON. Only map[string]any and []any are
// traversed as containers; every other type — including structs and typed maps
// such as map[string]string — is treated as an opaque scalar. Decode into `any`
// before walking if you need to reach inside.
//
// Walk mutates containers in place: replacing a value writes through to the
// caller's map or slice. Callers that must not modify their input should walk a
// copy, which a json.Unmarshal into a fresh `any` provides for free.
package deepmap

// Element represents a single element in the path to a value
type Element struct {
	Key   string // Key if map
	Index int    // Index if array
	IsMap bool   // true if this element is from a map, false if from array
}

// Kind represents the type of value being traversed
type Kind int

const (
	KindScalar Kind = iota // Basic types like string, int, bool, etc.
	KindMap                // map[string]any
	KindArray              // []any
	KindNil                // nil value
)

// Visitor represents a value in the traversal
type Visitor struct {
	Value    any
	Parent   any // Parent container (map or slice)
	Path     []Element
	Key      string // Key in parent map (empty for array elements)
	Kind     Kind
	Children int // Number of direct children
}

// Action represents what to do with the current value
type Action int

const (
	ActionKeep    Action = iota // Keep the current value
	ActionReplace               // Replace with new value
)

// Response represents the complete response from a visitor function
type Response struct {
	Action       Action // What to do with the value
	Value        any    // New value if Action is ActionReplace
	DoStopBranch bool   // Stop traversing current branch if true
	DoStopWalk   bool   // Stop entire walk if true
}

// Keep returns a Response that keeps the current value
func Keep() Response {
	return Response{Action: ActionKeep}
}

// Replace returns a Response that replaces the current value
func Replace(value any) Response {
	return Response{Action: ActionReplace, Value: value}
}

// WithStopBranch modifies a Response to stop traversing the current branch
func (r Response) WithStopBranch() Response {
	r.DoStopBranch = true
	return r
}

// WithStopWalk modifies a Response to stop the entire walk
func (r Response) WithStopWalk() Response {
	r.DoStopWalk = true
	return r
}

// getKind determines the type and number of children of a value
func getKind(v any) (Kind, int) {
	if v == nil {
		return KindNil, 0
	}

	switch val := v.(type) {
	case map[string]any:
		return KindMap, len(val)
	case []any:
		return KindArray, len(val)
	default:
		return KindScalar, 0
	}
}

// Walk traverses a nested map/slice structure and allows modifications
// Returns an iterator function that takes a modifier function
func Walk(data any) func(func(*Visitor) Response) {
	return func(yield func(*Visitor) Response) {
		if data == nil {
			return
		}

		var walk func(v any, parent any, path []Element, key string) any
		walk = func(v any, parent any, path []Element, key string) any {
			kind, children := getKind(v)
			visitor := &Visitor{
				Value:    v,
				Parent:   parent,
				Path:     path,
				Key:      key,
				Kind:     kind,
				Children: children,
			}

			resp := yield(visitor)

			// Handle value modification
			if resp.Action == ActionReplace {
				replaceInParent(visitor, resp.Value)
				v = resp.Value
				// Get updated kind after replacement
				kind, _ = getKind(v)
			}

			// Handle traversal control
			if resp.DoStopWalk || resp.DoStopBranch {
				return v
			}

			// Only traverse children if we haven't replaced with a scalar or nil
			if kind == KindMap {
				if m, ok := v.(map[string]any); ok {
					for k, child := range m {
						newPath := make([]Element, len(path)+1)
						copy(newPath, path)
						newPath[len(path)] = Element{Key: k, IsMap: true}
						if newChild := walk(child, m, newPath, k); newChild != nil {
							m[k] = newChild
						}
						if resp.DoStopWalk {
							return v
						}
					}
				}
			} else if kind == KindArray {
				if arr, ok := v.([]any); ok {
					for i, child := range arr {
						newPath := make([]Element, len(path)+1)
						copy(newPath, path)
						newPath[len(path)] = Element{Index: i}
						if newChild := walk(child, arr, newPath, ""); newChild != nil {
							arr[i] = newChild
						}
						if resp.DoStopWalk {
							return v
						}
					}
				}
			}
			return v
		}

		walk(data, nil, nil, "")
	}
}

// replaceInParent replaces a value in its parent container
func replaceInParent(visitor *Visitor, newValue any) {
	if visitor == nil || visitor.Parent == nil {
		return
	}

	switch parent := visitor.Parent.(type) {
	case map[string]any:
		parent[visitor.Key] = newValue
	case []any:
		if len(visitor.Path) > 0 {
			lastElem := visitor.Path[len(visitor.Path)-1]
			if !lastElem.IsMap && lastElem.Index >= 0 && lastElem.Index < len(parent) {
				parent[lastElem.Index] = newValue
			}
		}
	}
}
