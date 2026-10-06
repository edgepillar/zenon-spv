package main

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Bound token traversal before building typed values. Decode integers directly
// into integer fields: no float64 conversion, exponent spelling or silent null
// defaults. Duplicate keys include equivalent escaped spellings.
func decodeExact(raw []byte, destination any) bool {
	if !utf8.Valid(raw) || !consumerTokensBounded(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	if !scanValue(d, 0, &nodes) {
		return false
	}
	if _, err := d.Token(); err != io.EOF {
		return false
	}
	t := reflect.TypeOf(destination)
	if t.Kind() != reflect.Pointer || !exactShape(raw, t.Elem()) {
		return false
	}
	return json.Unmarshal(raw, destination) == nil
}

func scanValue(d *json.Decoder, depth int, nodes *int) bool {
	(*nodes)++
	if depth > 16 || *nodes > 16384 {
		return false
	}
	token, err := d.Token()
	if err != nil {
		return false
	}
	switch v := token.(type) {
	case json.Number:
		return len(v) <= maxConsumerNumberBytes && v != "-0" && !strings.ContainsAny(string(v), ".eE")
	case string:
		return len(v) <= maxConsumerStringBytes
	case json.Delim:
		switch v {
		case '{':
			keys := make(map[string]bool)
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || len(name) > 128 || keys[name] || len(keys) >= 256 {
					return false
				}
				keys[name] = true
				if !scanValue(d, depth+1, nodes) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			count := 0
			for d.More() {
				count++
				if count > maxTargets || !scanValue(d, depth+1, nodes) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	return true
}

// All fields are required, except explicitly tagged omitempty references.
// Nullable pointers model only the report's documented nullable fields. A
// present optional reference is never allowed to be null. Key matching is
// exact, unlike encoding/json's default case-insensitive struct matching.
func exactShape(raw []byte, t reflect.Type) bool {
	raw = bytes.TrimSpace(raw)
	if t.Kind() == reflect.Pointer {
		if bytes.Equal(raw, []byte("null")) {
			return true
		}
		return exactShape(raw, t.Elem())
	}
	if bytes.Equal(raw, []byte("null")) || len(raw) == 0 {
		return false
	}
	switch t.Kind() {
	case reflect.Struct:
		if raw[0] != '{' {
			return false
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			parts := strings.Split(field.Tag.Get("json"), ",")
			name := parts[0]
			value, exists := fields[name]
			optional := len(parts) == 2 && parts[1] == "omitempty"
			if !exists {
				if optional {
					continue
				}
				return false
			}
			if optional && bytes.Equal(bytes.TrimSpace(value), []byte("null")) || !exactShape(value, field.Type) {
				return false
			}
			delete(fields, name)
		}
		return len(fields) == 0
	case reflect.Slice:
		if raw[0] != '[' {
			return false
		}
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return false
		}
		for _, value := range values {
			if !exactShape(value, t.Elem()) {
				return false
			}
		}
	}
	return true // json.Unmarshal checks scalar types and integer ranges.
}
