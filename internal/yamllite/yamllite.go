// Package yamllite is a tiny, dependency-free YAML parser covering the subset
// Scout's config uses: block mappings, block sequences (of scalars or maps),
// flow mappings {a: b}, flow sequences [a, b], quoted/typed scalars, and #
// comments. It parses into a generic tree (map[string]any / []any / scalars);
// config.go maps that tree onto typed structs by hand (no reflection).
//
// It is intentionally small. It is not a full YAML implementation — no anchors,
// tags, multi-document streams, or block scalars (| >). That keeps Scout a
// single static binary with nothing to vendor.
package yamllite

import (
	"fmt"
	"strconv"
	"strings"
)

type line struct {
	indent int
	text   string
	num    int // 1-based source line for errors
}

// Parse parses YAML bytes into a generic tree. The top level is expected to be
// a mapping; an empty document yields an empty map.
func Parse(data []byte) (map[string]any, error) {
	lines, err := lex(string(data))
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return map[string]any{}, nil
	}
	val, _, err := parseNode(lines, 0)
	if err != nil {
		return nil, err
	}
	if m, ok := val.(map[string]any); ok {
		return m, nil
	}
	if val == nil {
		return map[string]any{}, nil
	}
	return nil, fmt.Errorf("top-level YAML must be a mapping")
}

func lex(data string) ([]line, error) {
	var out []line
	for n, raw := range strings.Split(data, "\n") {
		raw = strings.TrimRight(raw, "\r")
		content := stripComment(raw)
		if strings.TrimSpace(content) == "" {
			continue
		}
		indent := 0
		for indent < len(content) {
			c := content[indent]
			if c == ' ' {
				indent++
			} else if c == '\t' {
				return nil, fmt.Errorf("line %d: tab used for indentation (use spaces)", n+1)
			} else {
				break
			}
		}
		out = append(out, line{indent: indent, text: strings.TrimSpace(content), num: n + 1})
	}
	return out, nil
}

// stripComment removes a trailing '#' comment, respecting quotes. A '#' only
// starts a comment at column 0 or when preceded by whitespace.
func stripComment(s string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '#' && !inSingle && !inDouble:
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return s[:i]
			}
		}
	}
	return s
}

func isSeqItem(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

// parseNode parses the node beginning at lines[i], returning the value and the
// index of the next unconsumed line.
func parseNode(lines []line, i int) (any, int, error) {
	if isSeqItem(lines[i].text) {
		return parseSeq(lines, i, lines[i].indent)
	}
	return parseMap(lines, i, lines[i].indent)
}

func parseMap(lines []line, i, indent int) (any, int, error) {
	m := map[string]any{}
	for i < len(lines) {
		ln := lines[i]
		if ln.indent != indent || isSeqItem(ln.text) {
			break
		}
		key, rest, err := splitKey(ln.text)
		if err != nil {
			return nil, i, fmt.Errorf("line %d: %w", ln.num, err)
		}
		i++
		if rest == "" {
			// nested block value, or empty
			if i < len(lines) && (lines[i].indent > indent || (lines[i].indent == indent && isSeqItem(lines[i].text))) {
				var val any
				var err error
				if lines[i].indent == indent && isSeqItem(lines[i].text) {
					val, i, err = parseSeq(lines, i, indent)
				} else {
					val, i, err = parseNode(lines, i)
				}
				if err != nil {
					return nil, i, err
				}
				m[key] = val
			} else {
				m[key] = nil
			}
		} else {
			v, err := parseScalarOrFlow(rest)
			if err != nil {
				return nil, i, fmt.Errorf("line %d: %w", ln.num, err)
			}
			m[key] = v
		}
	}
	return m, i, nil
}

func parseSeq(lines []line, i, indent int) (any, int, error) {
	arr := []any{}
	for i < len(lines) {
		ln := lines[i]
		if ln.indent != indent || !isSeqItem(ln.text) {
			break
		}
		content := ""
		if ln.text != "-" {
			content = strings.TrimSpace(ln.text[2:])
		}
		i++
		if content == "" {
			// nested block item
			if i < len(lines) && lines[i].indent > indent {
				val, ni, err := parseNode(lines, i)
				if err != nil {
					return nil, i, err
				}
				arr = append(arr, val)
				i = ni
			} else {
				arr = append(arr, nil)
			}
			continue
		}
		if content[0] == '{' || content[0] == '[' {
			v, err := parseScalarOrFlow(content)
			if err != nil {
				return nil, i, fmt.Errorf("line %d: %w", ln.num, err)
			}
			arr = append(arr, v)
			continue
		}
		if colonIndex(content) >= 0 {
			// multi-line map item: gather continuation lines (indent > seq indent)
			var cont []line
			for i < len(lines) && lines[i].indent > indent {
				cont = append(cont, lines[i])
				i++
			}
			childIndent := indent + 2
			if len(cont) > 0 {
				childIndent = cont[0].indent
			}
			sub := append([]line{{indent: childIndent, text: content, num: ln.num}}, cont...)
			val, _, err := parseMap(sub, 0, childIndent)
			if err != nil {
				return nil, i, err
			}
			arr = append(arr, val)
			continue
		}
		v, err := parseScalarOrFlow(content)
		if err != nil {
			return nil, i, fmt.Errorf("line %d: %w", ln.num, err)
		}
		arr = append(arr, v)
	}
	return arr, i, nil
}

// splitKey splits "key: value" into key and value, respecting quotes.
func splitKey(text string) (string, string, error) {
	idx := colonIndex(text)
	if idx < 0 {
		return "", "", fmt.Errorf("expected 'key: value', got %q", text)
	}
	key := strings.TrimSpace(text[:idx])
	rest := strings.TrimSpace(text[idx+1:])
	key = unquote(key)
	return key, rest, nil
}

// colonIndex returns the index of the key/value separator colon (a ':' at depth
// 0 followed by a space or end-of-string), or -1.
func colonIndex(s string) int {
	inSingle, inDouble := false, false
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case (c == '{' || c == '[') && !inSingle && !inDouble:
			depth++
		case (c == '}' || c == ']') && !inSingle && !inDouble:
			depth--
		case c == ':' && !inSingle && !inDouble && depth == 0:
			if i == len(s)-1 || s[i+1] == ' ' {
				return i
			}
		}
	}
	return -1
}

func parseScalarOrFlow(s string) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	switch s[0] {
	case '{':
		return parseFlowMap(s)
	case '[':
		return parseFlowSeq(s)
	default:
		return parseScalar(s), nil
	}
}

func parseFlowMap(s string) (any, error) {
	if s[len(s)-1] != '}' {
		return nil, fmt.Errorf("unterminated flow mapping %q", s)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	m := map[string]any{}
	if inner == "" {
		return m, nil
	}
	for _, part := range splitFlow(inner) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := colonIndex(part)
		if idx < 0 {
			return nil, fmt.Errorf("flow mapping entry missing ':' in %q", part)
		}
		key := unquote(strings.TrimSpace(part[:idx]))
		val, err := parseScalarOrFlow(strings.TrimSpace(part[idx+1:]))
		if err != nil {
			return nil, err
		}
		m[key] = val
	}
	return m, nil
}

func parseFlowSeq(s string) (any, error) {
	if s[len(s)-1] != ']' {
		return nil, fmt.Errorf("unterminated flow sequence %q", s)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	arr := []any{}
	if inner == "" {
		return arr, nil
	}
	for _, part := range splitFlow(inner) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		val, err := parseScalarOrFlow(part)
		if err != nil {
			return nil, err
		}
		arr = append(arr, val)
	}
	return arr, nil
}

// splitFlow splits a flow body by top-level commas, respecting quotes/nesting.
func splitFlow(s string) []string {
	var out []string
	inSingle, inDouble := false, false
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case (c == '{' || c == '[') && !inSingle && !inDouble:
			depth++
		case (c == '}' || c == ']') && !inSingle && !inDouble:
			depth--
		case c == ',' && depth == 0 && !inSingle && !inDouble:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func parseScalar(s string) any {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return unquote(s)
		}
	}
	switch strings.ToLower(s) {
	case "null", "~":
		return nil
	case "true", "yes", "on":
		return true
	case "false", "no", "off":
		return false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return s
}

func unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] == '\'' && s[len(s)-1] == '\'' {
		inner := s[1 : len(s)-1]
		return strings.ReplaceAll(inner, "''", "'")
	}
	if s[0] == '"' && s[len(s)-1] == '"' {
		inner := s[1 : len(s)-1]
		if unq, err := strconv.Unquote(`"` + inner + `"`); err == nil {
			return unq
		}
		// Fall back: strip common escapes manually.
		r := strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\n`, "\n", `\t`, "\t")
		return r.Replace(inner)
	}
	return s
}
