// SPDX-License-Identifier: MIT

// Package jsonspan locates token boundaries in complete, already validated
// JSON. Callers keep the input stable and supply the first byte of the token.
package jsonspan

import "bytes"

// SpaceEnd advances past JSON whitespace.
func SpaceEnd(raw []byte, at int) int {
	for at < len(raw) {
		switch raw[at] {
		case ' ', '\t', '\r', '\n':
			at++
		default:
			return at
		}
	}
	return at
}

// StringEnd returns the first offset after a validated quoted string.
func StringEnd(raw []byte, at int) int {
	at++
	for {
		quote := at + bytes.IndexByte(raw[at:], '"')
		escaped := false
		for i := quote - 1; i >= at && raw[i] == '\\'; i-- {
			escaped = !escaped
		}
		at = quote + 1
		if !escaped {
			return at
		}
	}
}

// ValueEnd returns the first offset after a validated value.
func ValueEnd(raw []byte, at int) int {
	switch raw[at] {
	case '"':
		return StringEnd(raw, at)
	case '[', '{':
		depth := 1
		at++
		for depth > 0 {
			switch raw[at] {
			case '"':
				at = StringEnd(raw, at)
				continue
			case '[', '{':
				depth++
			case ']', '}':
				depth--
			}
			at++
		}
	default:
		for at < len(raw) {
			switch raw[at] {
			case ' ', '\t', '\r', '\n', ',', ']', '}':
				return at
			default:
				at++
			}
		}
	}
	return at
}
