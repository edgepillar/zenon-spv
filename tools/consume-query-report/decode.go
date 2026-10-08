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
