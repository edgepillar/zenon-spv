package main

import (
	"bytes"
	"testing"
)

var consumerReadSink []byte

// Raw reader allocations only: no filesystem, JSON, matching, process startup
// or RSS. The first four sizes are fixed offline consumer workload byte counts;
// repeated bytes are deliberately not a valid diagnostic or trust input.
func BenchmarkConsumerInputRead(b *testing.B) {
	for _, workload := range []struct {
		name  string
		size  int
		limit int64
	}{
		{"expectations_699", 699, maxExpectationsBytes},
		{"report_2264", 2264, maxReportBytes},
		{"expectations_55897", 55897, maxExpectationsBytes},
		{"report_157932", 157932, maxReportBytes},
		{"expectations_cap", maxExpectationsBytes, maxExpectationsBytes},
		{"report_cap", maxReportBytes, maxReportBytes},
	} {
		input := bytes.Repeat([]byte{0x81}, workload.size)
		for _, mode := range []string{"previous", "descriptor_hint"} {
			b.Run(workload.name+"/"+mode, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(workload.size))
				for b.Loop() {
					var raw []byte
					var err error
					if mode == "previous" {
						raw, err = referenceInputRead(bytes.NewReader(input), workload.limit)
					} else {
						raw, err = readInputBytes(bytes.NewReader(input), workload.limit, int64(workload.size))
					}
					if err != nil || !bytes.Equal(raw, input) {
						b.Fatal("measured reader changed the complete input")
					}
					consumerReadSink = raw
				}
			})
		}
	}
}
