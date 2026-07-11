package yamllite

import (
	"reflect"
	"testing"
)

func TestScalars(t *testing.T) {
	tree, err := Parse([]byte(`
a: hello
b: "quoted string"
c: 42
d: 3.14
e: true
f: false
g: null
h: 5m
`))
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]any{
		"a": "hello",
		"b": "quoted string",
		"c": 42,
		"d": 3.14,
		"e": true,
		"f": false,
		"g": nil,
		"h": "5m",
	}
	for k, want := range checks {
		if got := tree[k]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %#v want %#v", k, got, want)
		}
	}
}

func TestNestedMaps(t *testing.T) {
	tree, err := Parse([]byte(`
server:
  bind: 0.0.0.0
  port: "7711"
limits:
  timeout: 5m
  rate_limit: 240
`))
	if err != nil {
		t.Fatal(err)
	}
	srv, ok := tree["server"].(map[string]any)
	if !ok {
		t.Fatalf("server not a map: %#v", tree["server"])
	}
	if srv["bind"] != "0.0.0.0" || srv["port"] != "7711" {
		t.Errorf("server fields wrong: %#v", srv)
	}
	lim := tree["limits"].(map[string]any)
	if lim["timeout"] != "5m" || lim["rate_limit"] != 240 {
		t.Errorf("limits fields wrong: %#v", lim)
	}
}

func TestBlockSequence(t *testing.T) {
	tree, err := Parse([]byte(`
tokens:
  - alpha
  - "beta gamma"
  - 123
`))
	if err != nil {
		t.Fatal(err)
	}
	got := tree["tokens"].([]any)
	want := []any{"alpha", "beta gamma", 123}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v want %#v", got, want)
	}
}

func TestFlowSequenceAndMap(t *testing.T) {
	tree, err := Parse([]byte(`
shell: ["/bin/bash", "-lc"]
roots: ["/"]
rule: { pattern: "^git push", action: allow, reason: "ok here" }
`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tree["shell"], []any{"/bin/bash", "-lc"}) {
		t.Errorf("shell: %#v", tree["shell"])
	}
	if !reflect.DeepEqual(tree["roots"], []any{"/"}) {
		t.Errorf("roots: %#v", tree["roots"])
	}
	rule := tree["rule"].(map[string]any)
	if rule["pattern"] != "^git push" || rule["action"] != "allow" || rule["reason"] != "ok here" {
		t.Errorf("rule: %#v", rule)
	}
}

func TestSequenceOfInlineMaps(t *testing.T) {
	tree, err := Parse([]byte(`
rules:
  - { pattern: "a", action: deny }
  - { pattern: "b", action: ask, reason: "hmm" }
`))
	if err != nil {
		t.Fatal(err)
	}
	rules := tree["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
	r0 := rules[0].(map[string]any)
	r1 := rules[1].(map[string]any)
	if r0["pattern"] != "a" || r0["action"] != "deny" {
		t.Errorf("r0: %#v", r0)
	}
	if r1["reason"] != "hmm" {
		t.Errorf("r1: %#v", r1)
	}
}

func TestSequenceOfMultilineMaps(t *testing.T) {
	tree, err := Parse([]byte(`
rules:
  - pattern: "x"
    action: allow
    reason: "scratch"
  - pattern: "y"
    action: deny
`))
	if err != nil {
		t.Fatal(err)
	}
	rules := tree["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("want 2, got %d: %#v", len(rules), rules)
	}
	r0 := rules[0].(map[string]any)
	if r0["pattern"] != "x" || r0["action"] != "allow" || r0["reason"] != "scratch" {
		t.Errorf("r0: %#v", r0)
	}
	r1 := rules[1].(map[string]any)
	if r1["pattern"] != "y" || r1["action"] != "deny" {
		t.Errorf("r1: %#v", r1)
	}
}

func TestComments(t *testing.T) {
	tree, err := Parse([]byte(`
# a full comment
a: 1   # trailing comment
b: "has # hash inside"  # real comment
`))
	if err != nil {
		t.Fatal(err)
	}
	if tree["a"] != 1 {
		t.Errorf("a: %#v", tree["a"])
	}
	if tree["b"] != "has # hash inside" {
		t.Errorf("b: %#v", tree["b"])
	}
}

func TestTabIndentationError(t *testing.T) {
	_, err := Parse([]byte("a:\n\tb: 1\n"))
	if err == nil {
		t.Error("expected error for tab indentation")
	}
}

func TestEmpty(t *testing.T) {
	tree, err := Parse([]byte("\n\n# just comments\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tree) != 0 {
		t.Errorf("expected empty map, got %#v", tree)
	}
}
