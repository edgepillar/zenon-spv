package verify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Preserve field matching and unknown-field compatibility, but reject repeated
// top-level state fields. Later arrays, objects, or nulls must not hide earlier
// evidence from validation. Publish the decoded state only on complete success.
func (state *persistedState) UnmarshalJSON(raw []byte) error {
	var decoded persistedState
	fields := []struct {
		name   string
		target any
	}{
		{"version", &decoded.Version}, {"genesis", &decoded.Genesis},
		{"retained_window", &decoded.Window}, {"capacity", &decoded.Capacity},
		{"protocol_profile", &decoded.ProtocolProfile},
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return fmt.Errorf("%w: state file must be a JSON object", ErrInvalidRetainedState)
	}
	seen := make([]bool, len(fields))
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return fmt.Errorf("%w: invalid state field name", ErrInvalidRetainedState)
		}
		var ignored json.RawMessage
		var target any = &ignored
		for i, field := range fields {
			// Match the Unicode case folding used by encoding/json, after
			// JSON escapes have been resolved by Token.
			if !strings.EqualFold(name, field.name) {
				continue
			}
			if seen[i] {
				return fmt.Errorf("%w: duplicate state field %q", ErrInvalidRetainedState, field.name)
			}
			seen[i] = true
			target = field.target
			break
		}
		if err := d.Decode(target); err != nil {
			return err
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return fmt.Errorf("%w: invalid state object terminator", ErrInvalidRetainedState)
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing state JSON data", ErrInvalidRetainedState)
	}
	*state = decoded
	return nil
}
