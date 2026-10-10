package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Fixed raw stream capture only: no child process, report parsing, consumer,
// network, durability, process RSS or production budget is measured here.
func BenchmarkObserverQueryStaging(b *testing.B) {
	for _, size := range []int{0, 699, 55897, maxReportBytes} {
		raw := bytes.Repeat([]byte{0x81}, size)
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			for _, mode := range []string{"buffered_then_file", "streamed_file"} {
				b.Run(mode, func(b *testing.B) {
					path := filepath.Join(b.TempDir(), "query.json")
					b.ReportAllocs()
					b.SetBytes(int64(size))
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						out := &boundedOutput{limit: maxReportBytes, retain: mode == "buffered_then_file", cancel: func() { b.Fatal("unexpected cap refusal") }}
						var file *os.File
						if mode == "streamed_file" {
							var err error
							file, err = os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
							if err != nil {
								b.Fatal("cannot prepare capture destination")
							}
							out.destination = file
						}
						copyCollectorChunks(b, out, raw)
						if out.observed != int64(size) || out.exceeded || out.writeFailed {
							b.Fatal("capture changed bounded stream accounting")
						}
						if file != nil {
							if out.buffer.Len() != 0 || file.Close() != nil {
								b.Fatal("streaming retained bytes or failed to close")
							}
						} else if os.WriteFile(path, out.buffer.Bytes(), 0o600) != nil {
							b.Fatal("cannot publish buffered capture")
						}
					}
					b.StopTimer()
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, raw) {
						b.Fatal("capture changed complete raw bytes")
					}
				})
			}
		})
	}
}
