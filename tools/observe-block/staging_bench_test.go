package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x3639/zenon-spv/internal/verify"
)

// Compare the preserved parent capture/validation/staging sequence with direct
// private staging. No subprocess, retained-state validation or proof acceptance
// is measured here; the large syntax-only fixture has the full pipeline's wire
// size. Ordinary end-to-end observations are reported separately.
func BenchmarkCollectorStaging(b *testing.B) {
	for _, size := range []struct {
		name  string
		bytes int
	}{{"Small", 1024}, {"WireSized", 36374884}} {
		b.Run(size.name, func(b *testing.B) {
			raw := bytes.Repeat([]byte{'x'}, size.bytes)
			copy(raw, []byte(`{"data":"`))
			copy(raw[len(raw)-2:], []byte(`"}`))
			if !json.Valid(raw) {
				b.Fatal("cannot select syntax-only wire fixture")
			}
			for _, toFile := range []bool{false, true} {
				name := "buffered"
				if toFile {
					name = "file"
				}
				b.Run(name, func(b *testing.B) {
					path := filepath.Join(b.TempDir(), "candidate.json")
					b.ReportAllocs()
					b.SetBytes(int64(len(raw)))
					b.ResetTimer()
					for range b.N {
						if toFile {
							file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
							if err != nil {
								b.Fatal("cannot create private fixture")
							}
							out := boundedOutput{limit: int(verify.DefaultMaxBundleBytes), destination: file, cancel: func() {}}
							copyCollectorChunks(b, &out, raw)
							valid, readErr := stagedJSON(file, int64(len(raw)))
							closeErr := file.Close()
							if readErr != nil || closeErr != nil || !valid || out.buffer.Len() != 0 || out.observed != int64(len(raw)) {
								b.Fatal("completed staged bytes changed")
							}
						} else {
							out := boundedOutput{limit: int(verify.DefaultMaxBundleBytes), retain: true, cancel: func() {}}
							copyCollectorChunks(b, &out, raw)
							if !json.Valid(out.buffer.Bytes()) || os.WriteFile(path, out.buffer.Bytes(), 0o600) != nil || out.observed != int64(len(raw)) {
								b.Fatal("completed buffered bytes changed")
							}
						}
					}
					b.StopTimer()
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, raw) {
						b.Fatal("capture changed selected wire bytes")
					}
				})
			}
		})
	}
}

// os/exec's copying uses bounded chunks; keep the same selected 32 KiB chunk
// size in both paths rather than writing the whole fixture in one call.
func copyCollectorChunks(b *testing.B, out io.Writer, raw []byte) {
	b.Helper()
	for len(raw) > 0 {
		n := min(len(raw), 32<<10)
		if wrote, err := out.Write(raw[:n]); err != nil || wrote != n {
			b.Fatal("bounded capture changed chunk bytes")
		}
		raw = raw[n:]
	}
}
