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
// The page fixture uses the size and shape of the bounded candidate range.
// These are synthetic decoder allocation measurements.
func BenchmarkRPCEnvelopeExtensions(b *testing.B) {
	for _, size := range []int{32 << 10, 1 << 20, 8 << 20} {
		raw := []byte(`{"jsonrpc":"2.0","trace":{"metadata":"` + strings.Repeat("x", size) + `"},"id":1,"result":{"value":2}}`)
		benchmarkRPCEnvelopeFields(b, fmt.Sprint(size), raw, []byte(`{"value":2}`))
	}

	const prefix = `{"jsonrpc":"2.0","id":1,"result":`
	const rowCount = 400
	data := strings.Repeat("Z", 20<<10)
	row := `{"data":"` + data + `"}`
	raw := make([]byte, 0, len(prefix)+rowCount*(len(row)+1)+32)
	raw = append(raw, prefix...)
	raw = append(raw, `{"list":[`...)
	for i := 0; i < rowCount; i++ {
		if i > 0 {
			raw = append(raw, ',')
		}
		raw = append(raw, row...)
	}
	raw = append(raw, `],"count":400}}`...)
	result := raw[len(prefix) : len(raw)-1]
	benchmarkRPCEnvelopeFields(b, "page_result", raw, result)
	for _, mode := range []struct {
		name   string
		decode func([]byte, *[]rpcMomentum) error
	}{
		{"streaming_reference", func(raw []byte, rows *[]rpcMomentum) error {
			return json.Unmarshal(raw, &referenceRPCRangeDecoder{
				target: rows, count: rowCount, rowTarget: newRPCEvidenceDecoder().momentum,
			})
		}},
		{"borrowed_rows", func(raw []byte, rows *[]rpcMomentum) error {
			decoder := rpcListDecoder[rpcMomentum]{target: rows, count: rowCount, rowTarget: newRPCEvidenceDecoder().momentum}
			return decoder.UnmarshalJSON(raw)
		}},
	} {
		b.Run("page_rows/"+mode.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(result)))
			for i := 0; i < b.N; i++ {
				var rows []rpcMomentum
				if err := mode.decode(result, &rows); err != nil || len(rows) != rowCount || rows[0].Data != data || rows[rowCount-1].Data != data {
					b.Fatalf("range row projection mismatch: %v", err)
				}
			}
		})
	}
}

func benchmarkRPCEnvelopeFields(b *testing.B, name string, raw, expected []byte) {
	b.Helper()
	for _, mode := range []struct {
		name   string
		decode func([]byte, map[string]*json.RawMessage) error
	}{
		{"copy_reference", decodeRPCObjectCopyReference},
		{"discard_extension", decodeRPCObject},
	} {
		b.Run(name+"/"+mode.name, func(b *testing.B) {
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
					!bytes.Equal(result, expected) || len(remoteError) != 0 {
					b.Fatalf("control field mismatch: %v", err)
				}
			}
		})
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
