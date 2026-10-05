package fetch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

// BenchmarkRPCEnvelopeExtensions compares the current object decoder with the
// former copy-based decoder retained below. Input construction is outside the
// timed region; both paths retain and check identical control-field bytes.
// These are synthetic decoder allocation observations, not RPC/RSS budgets.
func BenchmarkRPCEnvelopeExtensions(b *testing.B) {
	for _, size := range []int{32 << 10, 1 << 20, 8 << 20} {
		raw := []byte(`{"jsonrpc":"2.0","trace":{"metadata":"` + strings.Repeat("x", size) + `"},"id":1,"result":{"value":2}}`)
		for _, mode := range []struct {
			name   string
			decode func([]byte, map[string]*json.RawMessage) error
		}{
			{"copy_reference", decodeRPCObjectCopyReference},
			{"discard_extension", decodeRPCObject},
		} {
			b.Run(fmt.Sprintf("%d/%s", size, mode.name), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var version, id, result, remoteError json.RawMessage
					fields := map[string]*json.RawMessage{
						"jsonrpc": &version, "id": &id, "result": &result, "error": &remoteError,
					}
					if err := mode.decode(raw, fields); err != nil ||
						string(version) != `"2.0"` || string(id) != "1" ||
						string(result) != `{"value":2}` || len(remoteError) != 0 {
						b.Fatalf("control field mismatch: %v", err)
					}
				}
			})
		}
	}
}

// decodeRPCObjectCopyReference preserves the exact helper body from
// d25b0cd690fff9baf5ed3b447d948662b50233fd for the allocation comparison.
// It is compiled only in tests and is not used by production decoding.
func decodeRPCObjectCopyReference(raw []byte, fields map[string]*json.RawMessage) error {
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
		if !known {
			for field := range fields {
				if strings.EqualFold(name, field) {
					return fmt.Errorf("%w: noncanonical control field name", ErrInvalidRPCResponse)
				}
			}
			var ignored json.RawMessage
			target = &ignored
		} else if len(*target) != 0 {
			return fmt.Errorf("%w: duplicate control field", ErrInvalidRPCResponse)
		}
		if err := dec.Decode(target); err != nil {
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
