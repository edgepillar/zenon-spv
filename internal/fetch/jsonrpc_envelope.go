package fetch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidRPCResponse means that the bounded response envelope is malformed
// or does not identify this request. No result has been decoded into caller output.
var ErrInvalidRPCResponse = errors.New("invalid JSON-RPC response")

// decodeRPCResponse consumes a body already bounded by Client.Call. The client
// emits integer IDs; a response must echo that integer and use JSON-RPC 2.0.
// A successful result borrows bytes from raw until the caller decodes it.
func decodeRPCResponse(raw []byte, requestID int) (rpcResponse, error) {
	var versionRaw, idRaw, resultRaw, errorRaw json.RawMessage
	if err := decodeRPCObject(raw, map[string]*json.RawMessage{
		"jsonrpc": &versionRaw, "id": &idRaw, "result": &resultRaw, "error": &errorRaw,
	}); err != nil {
		return rpcResponse{}, err
	}
	var version string
	if json.Unmarshal(versionRaw, &version) != nil || version != "2.0" {
		return rpcResponse{}, fmt.Errorf("%w: jsonrpc must be 2.0", ErrInvalidRPCResponse)
	}
	var id *int
	if json.Unmarshal(idRaw, &id) != nil || id == nil || *id != requestID {
		return rpcResponse{}, fmt.Errorf("%w: id must match the request integer", ErrInvalidRPCResponse)
	}
	if (len(resultRaw) == 0) == (len(errorRaw) == 0) {
		return rpcResponse{}, fmt.Errorf("%w: exactly one of result or error is required", ErrInvalidRPCResponse)
	}
	if len(resultRaw) != 0 {
		return rpcResponse{Result: resultRaw}, nil
	}

	var codeRaw, messageRaw json.RawMessage
	if err := decodeRPCObject(errorRaw, map[string]*json.RawMessage{
		"code": &codeRaw, "message": &messageRaw, "data": nil,
	}); err != nil {
		return rpcResponse{}, err
	}
	var code *int
	var message *string
	if json.Unmarshal(codeRaw, &code) != nil || code == nil ||
		json.Unmarshal(messageRaw, &message) != nil || message == nil {
		return rpcResponse{}, fmt.Errorf("%w: error requires an integer code and string message", ErrInvalidRPCResponse)
	}
	return rpcResponse{Error: &rpcError{Code: *code, Message: *message}}, nil
}

// decodeRPCObject rejects duplicate control fields and case aliases while
// allowing unrelated extension members. Field names and values are not echoed
// in parser diagnostics. Callers provide fresh temporary fields for each object.
// Selected fields borrow the validated value bytes from raw.
// A nil target marks a known field whose value is discarded after JSON scanning;
// its presence is still tracked to reject duplicates and case aliases.
func decodeRPCObject(raw []byte, fields map[string]*json.RawMessage) error {
	const whitespace = " \t\r\n"
	raw = bytes.Trim(raw, whitespace)
	if len(raw) == 0 || raw[0] != '{' {
		return fmt.Errorf("%w: expected an object", ErrInvalidRPCResponse)
	}
	if len(raw) < 2 || raw[len(raw)-1] != '}' {
		return fmt.Errorf("%w: malformed object ending", ErrInvalidRPCResponse)
	}

	var discarded map[string]bool
	remaining := bytes.TrimLeft(raw[1:len(raw)-1], whitespace)
	for len(remaining) != 0 {
		if remaining[0] != '"' {
			return fmt.Errorf("%w: malformed object member", ErrInvalidRPCResponse)
		}
		keyEnd := rpcJSONStringEnd(remaining)
		var name string
		if json.Unmarshal(remaining[:keyEnd], &name) != nil {
			return fmt.Errorf("%w: malformed object member", ErrInvalidRPCResponse)
		}
		target, known := fields[name]
		if !known {
			for field := range fields {
				if strings.EqualFold(name, field) {
					return fmt.Errorf("%w: noncanonical control field name", ErrInvalidRPCResponse)
				}
			}
		} else if target == nil {
			if discarded[name] {
				return fmt.Errorf("%w: duplicate control field", ErrInvalidRPCResponse)
			}
			if discarded == nil {
				discarded = make(map[string]bool)
			}
			discarded[name] = true
		} else if len(*target) != 0 {
			return fmt.Errorf("%w: duplicate control field", ErrInvalidRPCResponse)
		}
		colon := bytes.TrimLeft(remaining[keyEnd:], whitespace)
		if len(colon) == 0 || colon[0] != ':' {
			return fmt.Errorf("%w: malformed member value", ErrInvalidRPCResponse)
		}
		value := bytes.TrimLeft(colon[1:], whitespace)
		end := rpcJSONValueEnd(value)
		// Validate each value with the standard decoder's grammar and depth
		// limit without allocating Decoder.Decode's whole-value buffer.
		if !json.Valid(value[:end]) {
			return fmt.Errorf("%w: malformed member value", ErrInvalidRPCResponse)
		}
		if target != nil {
			*target = value[:end:end]
		}
		remaining = bytes.TrimLeft(value[end:], whitespace)
		if len(remaining) == 0 {
			break
		}
		if remaining[0] != ',' {
			return fmt.Errorf("%w: malformed object member separator", ErrInvalidRPCResponse)
		}
		remaining = bytes.TrimLeft(remaining[1:], whitespace)
		if len(remaining) == 0 {
			return fmt.Errorf("%w: malformed object member", ErrInvalidRPCResponse)
		}
	}
	return nil
}

// rpcJSONValueEnd finds a possible value boundary without interpreting scalar
// syntax or matching bracket types. The caller validates the resulting span.
func rpcJSONValueEnd(raw []byte) int {
	depth := 0
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			i += rpcJSONStringEnd(raw[i:]) - 1
			if depth == 0 {
				return i + 1
			}
		case '{', '[':
			depth++
		case '}', ']':
			if depth == 0 {
				return i
			}
			depth--
			if depth == 0 {
				return i + 1
			}
		case ',', ' ', '\t', '\r', '\n':
			if depth == 0 {
				return i
			}
		}
	}
	return len(raw)
}

// rpcJSONStringEnd starts at the opening quote and skips escaped characters.
func rpcJSONStringEnd(raw []byte) int {
	for i := 1; i < len(raw); i++ {
		switch raw[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(raw)
}
