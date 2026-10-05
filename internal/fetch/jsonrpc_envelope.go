package fetch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrInvalidRPCResponse means that the bounded response envelope is malformed
// or does not identify this request. No result has been decoded into caller output.
var ErrInvalidRPCResponse = errors.New("invalid JSON-RPC response")

// decodeRPCResponse consumes a body already bounded by Client.Call. The client
// emits integer IDs; a response must echo that integer and use JSON-RPC 2.0.
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

	var codeRaw, messageRaw, dataRaw json.RawMessage
	if err := decodeRPCObject(errorRaw, map[string]*json.RawMessage{
		"code": &codeRaw, "message": &messageRaw, "data": &dataRaw,
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
func decodeRPCObject(raw []byte, fields map[string]*json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return fmt.Errorf("%w: expected an object", ErrInvalidRPCResponse)
	}
	for dec.More() {
		token, err := dec.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return fmt.Errorf("%w: malformed object member", ErrInvalidRPCResponse)
		}
		target, known := fields[name]
		var value any = target
		if !known {
			for field := range fields {
				if strings.EqualFold(name, field) {
					return fmt.Errorf("%w: noncanonical control field name", ErrInvalidRPCResponse)
				}
			}
			value = &ignoredRPCValue{}
		} else if len(*target) != 0 {
			return fmt.Errorf("%w: duplicate control field", ErrInvalidRPCResponse)
		}
		if err := dec.Decode(value); err != nil {
			return fmt.Errorf("%w: malformed member value", ErrInvalidRPCResponse)
		}
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') {
		return fmt.Errorf("%w: malformed object ending", ErrInvalidRPCResponse)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%w: trailing response data", ErrInvalidRPCResponse)
	}
	return nil
}

// ignoredRPCValue is only passed to json.Decoder.Decode, which scans and
// validates the complete JSON value before calling UnmarshalJSON. The callback
// discards that validated value without making a RawMessage payload copy.
// Decoder buffering and copies of required control fields are still allocated.
type ignoredRPCValue struct{}

func (*ignoredRPCValue) UnmarshalJSON([]byte) error { return nil }
