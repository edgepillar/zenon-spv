package fetch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

// BenchmarkRPCErrorData compares complete error-envelope decoding. The former
// response and object helpers below retain error.data; the current path can
// discard it. Input construction is outside the timed region. Both paths check
// the same remote-error outcome. These observations are not HTTP or RSS budgets.
func BenchmarkRPCErrorData(b *testing.B) {
	for _, size := range []int{32 << 10, 1 << 20, 8 << 20} {
		raw := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"failure","data":{"detail":"` + strings.Repeat("x", size) + `"}}}`)
		for _, mode := range []struct {
			name   string
			decode func([]byte, int) (rpcResponse, error)
		}{
			{"copy_reference", decodeRPCResponseErrorDataCopyReference},
			{"discard_error_data", decodeRPCResponse},
		} {
			b.Run(fmt.Sprintf("%d/%s", size, mode.name), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					r, err := mode.decode(raw, 1)
					if err != nil || len(r.Result) != 0 || r.Error == nil ||
						r.Error.Code != -1 || r.Error.Message != "failure" {
						b.Fatalf("remote error changed: %v", err)
					}
				}
			})
		}
	}
}

// These test-only helpers preserve the exact response and object decoder bodies
// from 6b14366b6f47ae8fd8d929899054402b60bc9e6c, with only function names changed.
// They are never used by production decoding.
func decodeRPCResponseErrorDataCopyReference(raw []byte, requestID int) (rpcResponse, error) {
	var versionRaw, idRaw, resultRaw, errorRaw json.RawMessage
	if err := decodeRPCObjectErrorDataCopyReference(raw, map[string]*json.RawMessage{
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
	if err := decodeRPCObjectErrorDataCopyReference(errorRaw, map[string]*json.RawMessage{
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
func decodeRPCObjectErrorDataCopyReference(raw []byte, fields map[string]*json.RawMessage) error {
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
