package overrides

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// Limits on a document: a document of every key is under 1 KiB, so these are for
// hostile input.
const (
	maxDocument = 16 << 10 // bytes of engine_overrides_json
	maxProblems = 16       // problems that Parse reports; the rest is counted
	maxDirLen   = 128      // bytes of a Dir
)

// ProblemClass says what is wrong with an engine_overrides_json.
type ProblemClass int

// The classes of problem.
const (
	// ProblemMalformed is a document that is not a JSON object, is too big, or
	// has a key twice.
	ProblemMalformed ProblemClass = iota + 1
	// ProblemOwned is a key that Postern owns (see Owned).
	ProblemOwned
	// ProblemUnsupported is a key that is neither whitelisted nor owned.
	ProblemUnsupported
	// ProblemInvalid is a whitelisted key with a value of the wrong type or
	// outside its range.
	ProblemInvalid
	// ProblemMore stands for the problems that are not listed.
	ProblemMore
)

// Problem is one thing that is wrong with an engine_overrides_json.
type Problem struct {
	Class ProblemClass
	// Key is the key that it is about; empty for the document as a whole.
	Key string
	// Msg is a sentence for an admin. It names the key, says what is allowed, and
	// never repeats a value.
	Msg string
}

// Parse reads and checks an engine_overrides_json, the JSON object of the
// overrides of a proxy. Empty, whitespace, "null" and "{}" are no overrides. It
// returns the overrides in the order of the table, or, when anything at all is
// wrong, no overrides and every problem, sorted by key (at most 16 of them
// and then one that counts the rest): a document is taken whole or not at all.
//
// Everything that is checked is checked here, and only here, so that the panel,
// the node and the driver cannot disagree:
//
//   - the document is a JSON object, of at most 16 KiB, with no key twice;
//   - every key is whitelisted, with a value of its type and in its range, and
//     is neither owned by Postern nor unknown.
func Parse(raw string) (Set, []Problem) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if len(raw) > maxDocument {
		return nil, []Problem{{Class: ProblemMalformed, Msg: fmt.Sprintf("engine_overrides_json is larger than %d KiB", maxDocument>>10)}}
	}
	fields, ok := decodeObject(raw)
	if !ok {
		return nil, []Problem{{Class: ProblemMalformed, Msg: "engine_overrides_json is not a JSON object"}}
	}

	// By key, so that the problems come in an order that does not depend on the
	// order of the document. A key that is given twice counts once, with the
	// value that came last, as encoding/json takes it.
	slices.SortStableFunc(fields, func(a, b field) int { return strings.Compare(a.key, b.key) })
	var (
		set      Set
		problems []Problem
	)
	for start := 0; start < len(fields); {
		end := start + 1
		for end < len(fields) && fields[end].key == fields[start].key {
			end++
		}
		key, value, repeats := fields[start].key, fields[end-1].raw, end-start
		start = end
		name := quoteKey(key)
		if repeats > 1 {
			problems = append(problems, Problem{Class: ProblemMalformed, Key: key, Msg: fmt.Sprintf("engine override %s is given more than once", name)})
		}
		if spec, ok := byKey[key]; ok {
			v, why := spec.read(value)
			if why != "" {
				problems = append(problems, Problem{Class: ProblemInvalid, Key: key, Msg: fmt.Sprintf("engine override %s %s", name, why)})
				continue
			}
			set = append(set, v)
			continue
		}
		if reason, ok := Owned(key); ok {
			problems = append(problems, Problem{Class: ProblemOwned, Key: key,
				Msg: fmt.Sprintf("engine override %s is owned by Postern and cannot be set: %s", name, reason)})
			continue
		}
		msg := fmt.Sprintf("engine override %s is not supported", name)
		if bytes.HasPrefix(bytes.TrimSpace(value), []byte("{")) {
			msg += `: overrides are flat keys such as "fast_mode", not tables`
		}
		problems = append(problems, Problem{Class: ProblemUnsupported, Key: key, Msg: msg})
	}

	if len(problems) > 0 {
		if extra := len(problems) - maxProblems; extra > 0 {
			problems = append(problems[:maxProblems:maxProblems],
				Problem{Class: ProblemMore, Msg: fmt.Sprintf("and %d more problems with engine_overrides_json", extra)})
		}
		return nil, problems
	}
	slices.SortFunc(set, func(a, b Value) int { return order[a.Key] - order[b.Key] })
	return set, nil
}

// quoteKey is a key for a message: quoted, so that no control character shows
// raw, and cut short, so that a hostile key cannot fill a log.
func quoteKey(key string) string { return fmt.Sprintf("%.64q", key) }

type field struct {
	key string
	raw json.RawMessage
}

// decodeObject reads a JSON object, or null (which is no fields), with the keys
// in the order of the document and nothing after it. It is not encoding/json's
// Unmarshal into a map, which would take a key given twice without a word.
func decodeObject(raw string) ([]field, bool) {
	dec := json.NewDecoder(strings.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, false
	}
	var fields []field
	switch tok := tok.(type) {
	case nil: // null
	case json.Delim:
		if tok != '{' {
			return nil, false
		}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, false
			}
			key, ok := keyTok.(string)
			if !ok {
				return nil, false
			}
			var value json.RawMessage
			if err := dec.Decode(&value); err != nil {
				return nil, false
			}
			fields = append(fields, field{key: key, raw: value})
		}
		if _, err := dec.Token(); err != nil { // the closing brace
			return nil, false
		}
	default:
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return fields, true
}

// read checks the JSON value of a key against its spec. It returns what is
// wrong, as the end of a sentence about the key, or "".
func (s Spec) read(raw json.RawMessage) (Value, string) {
	v := Value{Spec: s}
	v.Values = slices.Clone(s.Values) // the value is the caller's: the table stays as it is
	raw = bytes.TrimSpace(raw)
	switch s.Kind {
	case Bool:
		switch string(raw) {
		case "true":
			v.Bool = true
		case "false":
		default:
			return v, "must be true or false"
		}
	case Int:
		n, ok := readInt(raw)
		if !ok || n < s.Min || n > s.Max {
			return v, fmt.Sprintf("must be an integer from %d to %d", s.Min, s.Max)
		}
		v.Int = n
	case Enum:
		str, ok := readString(raw)
		if !ok || !slices.Contains(s.Values, str) {
			quoted := make([]string, len(s.Values))
			for i, value := range s.Values {
				quoted[i] = strconv.Quote(value)
			}
			return v, "must be one of " + strings.Join(quoted, ", ")
		}
		v.Str = str
	case Dir:
		str, ok := readString(raw)
		if !ok {
			return v, "must be a string"
		}
		if why := dirProblem(str); why != "" {
			return v, why
		}
		v.Str = str
	}
	return v, ""
}

// readInt reads a JSON number that is a whole number written as one: digits, and
// a minus sign. 1.0 and 1e2 are numbers to JSON, and not what a count is
// written as.
func readInt(raw []byte) (int64, bool) {
	digits := bytes.TrimPrefix(raw, []byte("-"))
	if len(digits) == 0 {
		return 0, false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	return n, err == nil
}

// readString reads a JSON string, and nothing else: null is not an empty one.
func readString(raw []byte) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// dirProblem checks the name of a directory that the engine keeps something in,
// which is a path below its data directory: relative, of plain ASCII, and with no
// component that is empty, "." or "..". It returns what is wrong, or "".
func dirProblem(s string) string {
	switch {
	case s == "":
		return `must not be empty (leave the key out for the default of telemt, "tlsfront")`
	case len(s) > maxDirLen:
		return fmt.Sprintf("must be at most %d bytes", maxDirLen)
	case s[0] == '/':
		return "must be relative, a directory below the data directory of the engine, and not an absolute path"
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' && c != '/' {
			return "may only have the letters a-z and A-Z, digits, '.', '_', '-' and '/' between directories"
		}
	}
	for part := range strings.SplitSeq(s, "/") {
		if part == "" || part == "." || part == ".." {
			return `must not have an empty, "." or ".." directory in it`
		}
	}
	return ""
}
