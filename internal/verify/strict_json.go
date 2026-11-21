package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// decodeRequiredObject accepts exactly the named fields, once each, with no
// null values. Callers bound raw before decoding and supply temporary targets
// so a failure cannot change an already selected trust configuration.
// A function target consumes one value directly and checks its non-null shape.
func decodeRequiredObject(raw []byte, fields map[string]any) error {
	return decodeRequiredObjectValue(json.NewDecoder(bytes.NewReader(raw)), fields, false)
}

// With requireUTF8, field names must be ASCII schema names. A function target
// also validates the raw text of each value it consumes.
func decodeRequiredObjectValue(d *json.Decoder, fields map[string]any, requireUTF8 bool) error {
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("expected one JSON object")
	}
	seen := make(map[string]bool, len(fields))
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return errors.New("malformed JSON object")
		}
		key, ok := token.(string)
		target, known := fields[key]
		if !ok || !known || seen[key] {
			return errors.New("unknown or duplicate field")
		}
		seen[key] = true
		if readValue, ok := target.(func(*json.Decoder) error); ok {
			if err := readValue(d); err != nil {
				return fmt.Errorf("invalid %s", key)
			}
			continue
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return errors.New("malformed JSON field")
		}
		if requireUTF8 && !utf8.Valid(value) {
			return fmt.Errorf("invalid %s", key)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("%s must be non-null", key)
		}
		if err := json.Unmarshal(value, target); err != nil {
			// Echo only known schema fields, never untrusted names or values.
			return fmt.Errorf("invalid %s", key)
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return errors.New("malformed JSON object")
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		return errors.New("trailing JSON")
	}
	if len(seen) != len(fields) {
		return errors.New("missing required field")
	}
	return nil
}
