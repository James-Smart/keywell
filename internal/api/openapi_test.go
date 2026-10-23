package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// operationMethods are the keys of an OpenAPI path item that are
// operations; the others (parameters, summary, ...) are not.
var operationMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true, "trace": true,
}

// TestOpenAPIMatchesRoutes checks that openapi.json describes exactly the
// routes table: every route is in paths under its lower-case method, and
// every operation in paths is a route. Each operation has a summary and at
// least one response.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openAPIDoc, &doc); err != nil {
		t.Fatalf("openapi.json: %v", err)
	}

	isRoute := map[string]bool{}
	for _, rt := range routes {
		method := strings.ToLower(rt.method)
		isRoute[method+" "+rt.path] = true
		if _, ok := doc.Paths[rt.path][method]; !ok {
			t.Errorf("route %s %s is not in openapi.json", rt.method, rt.path)
		}
	}

	for path, item := range doc.Paths {
		for method, raw := range item {
			if !operationMethods[method] {
				continue
			}
			if !isRoute[method+" "+path] {
				t.Errorf("openapi.json describes %s %s, which is not a route", strings.ToUpper(method), path)
			}
			var op struct {
				Summary   string                     `json:"summary"`
				Responses map[string]json.RawMessage `json:"responses"`
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Errorf("%s %s: %v", method, path, err)
				continue
			}
			if op.Summary == "" || len(op.Responses) == 0 {
				t.Errorf("%s %s: summary %q and %d responses, want both", method, path, op.Summary, len(op.Responses))
			}
		}
	}
}

// TestOpenAPIRefsResolve checks that every $ref in openapi.json points at
// something in the document.
func TestOpenAPIRefsResolve(t *testing.T) {
	var doc any
	if err := json.Unmarshal(openAPIDoc, &doc); err != nil {
		t.Fatalf("openapi.json: %v", err)
	}
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, child := range v {
				if ref, ok := child.(string); ok && k == "$ref" {
					if !resolves(doc, ref) {
						t.Errorf("$ref %q points at nothing", ref)
					}
					continue
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)
}

// resolves reports whether ref, a local reference like
// "#/components/schemas/Error", names a value in doc.
func resolves(doc any, ref string) bool {
	path, ok := strings.CutPrefix(ref, "#/")
	if !ok {
		return false
	}
	v := doc
	for name := range strings.SplitSeq(path, "/") {
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		if v, ok = m[strings.NewReplacer("~1", "/", "~0", "~").Replace(name)]; !ok {
			return false
		}
	}
	return true
}
