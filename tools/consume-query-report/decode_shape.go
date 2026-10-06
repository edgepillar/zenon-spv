package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

type shapeField struct {
	name     string
	typeOf   reflect.Type
	optional bool
}

type shapeCursor struct {
	raw    []byte
	at     int
	fields map[reflect.Type][]shapeField
}

// This traversal runs only after scanValue has checked the complete document's
// syntax, duplicate keys and resource bounds. It borrows byte spans rather than
// copying every nested value into RawMessage. The final json.Unmarshal still
// checks scalar types and integer ranges and builds the destination.
func exactShape(raw []byte, t reflect.Type) bool {
	s := shapeCursor{raw: raw, fields: make(map[reflect.Type][]shapeField)}
	if !s.value(t) {
		return false
	}
	s.space()
	return s.at == len(raw)
}

func (s *shapeCursor) space() {
	for s.at < len(s.raw) {
		switch s.raw[s.at] {
		case ' ', '\t', '\r', '\n':
			s.at++
		default:
			return
		}
	}
}

func (s *shapeCursor) take(c byte) bool {
	s.space()
	if s.at == len(s.raw) || s.raw[s.at] != c {
		return false
	}
	s.at++
	return true
}

func (s *shapeCursor) isNull() bool {
	return bytes.HasPrefix(s.raw[s.at:], []byte("null"))
}

func (s *shapeCursor) value(t reflect.Type) bool {
	s.space()
	if s.at == len(s.raw) {
		return false
	}
	if t.Kind() == reflect.Pointer {
		if s.isNull() {
			s.at += 4
			return true
		}
		return s.value(t.Elem())
	}
	if s.isNull() {
		return false
	}
	switch t.Kind() {
	case reflect.Struct:
		return s.object(t)
	case reflect.Slice:
		if !s.take('[') {
			return false
		}
		if s.take(']') {
			return true
		}
		for {
			if !s.value(t.Elem()) {
				return false
			}
			if s.take(']') {
				return true
			}
			if !s.take(',') {
				return false
			}
		}
	default:
		return s.skipValue()
	}
}

func (s *shapeCursor) object(t reflect.Type) bool {
	if !s.take('{') {
		return false
	}
	fields, ok := s.fields[t]
	if !ok {
		fields = make([]shapeField, t.NumField())
		for i := range fields {
			field := t.Field(i)
			parts := strings.Split(field.Tag.Get("json"), ",")
			fields[i] = shapeField{parts[0], field.Type, len(parts) == 2 && parts[1] == "omitempty"}
		}
		s.fields[t] = fields
	}
	var local [64]bool
	seen := local[:]
	if len(fields) > len(local) {
		seen = make([]bool, len(fields))
	}
	if !s.take('}') {
		for {
			s.space()
			raw, escaped, ok := s.stringSpan()
			if !ok || !s.take(':') {
				return false
			}
			name := string(raw[1 : len(raw)-1])
			if escaped && json.Unmarshal(raw, &name) != nil {
				return false
			}
			index := -1
			for i, field := range fields {
				if field.name == name {
					index = i
					break
				}
			}
			if index == -1 || seen[index] {
				return false
			}
			seen[index] = true
			s.space()
			if fields[index].optional && s.isNull() || !s.value(fields[index].typeOf) {
				return false
			}
			if s.take('}') {
				break
			}
			if !s.take(',') {
				return false
			}
		}
	}
	for i, field := range fields {
		if !seen[i] && !field.optional {
			return false
		}
	}
	return true
}

// Strings have already passed JSON/UTF-8 and decoded-length checks. Honor each
// escape pair while finding the closing quote; only escaped keys need decoding.
func (s *shapeCursor) stringSpan() ([]byte, bool, bool) {
	if s.at == len(s.raw) || s.raw[s.at] != '"' {
		return nil, false, false
	}
	start, escaped := s.at, false
	s.at++
	for s.at < len(s.raw) {
		switch s.raw[s.at] {
		case '\\':
			escaped = true
			s.at += 2
		case '"':
			s.at++
			return s.raw[start:s.at], escaped, true
		default:
			s.at++
		}
	}
	return nil, false, false
}

func (s *shapeCursor) skipValue() bool {
	s.space()
	if s.at == len(s.raw) {
		return false
	}
	if s.raw[s.at] == '"' {
		_, _, ok := s.stringSpan()
		return ok
	}
	if s.raw[s.at] == '{' || s.raw[s.at] == '[' {
		depth := 1
		s.at++
		for s.at < len(s.raw) {
			switch s.raw[s.at] {
			case '"':
				if _, _, ok := s.stringSpan(); !ok {
					return false
				}
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
			s.at++
			if depth == 0 {
				return true
			}
		}
		return false
	}
	start := s.at
	for s.at < len(s.raw) && !strings.ContainsRune(",]} \t\r\n", rune(s.raw[s.at])) {
		s.at++
	}
	return s.at != start
}
