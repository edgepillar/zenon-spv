package main

import (
	"bytes"
	"testing"
)

var observerReadSink []byte

// Raw reader allocations only: no filesystem, parsing, process startup, RSS or
// proof acceptance. The two middle sizes are fixed prior consumer byte counts;
// repeated bytes deliberately are not expectations, a diagnostic or trust input.
func BenchmarkObserverExpectationsRead(b *testing.B) {
	for _, workload := range []struct {
		name string
		size int
	}{{"empty", 0}, {"expectations_699", 699}, {"expectations_55897", 55897}, {"expectations_cap", maxExpectationsBytes}} {
		input := bytes.Repeat([]byte{0x81}, workload.size)
		for _, mode := range []string{"previous", "descriptor_hint"} {
			b.Run(workload.name+"/"+mode, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(workload.size))
				for b.Loop() {
					var raw []byte
					var err error
					if mode == "previous" {
						raw, err = previousExpectationBytes(bytes.NewReader(input), maxExpectationsBytes)
					} else {
						raw, err = readExpectationBytes(bytes.NewReader(input), maxExpectationsBytes, int64(workload.size))
					}
					if err != nil || !bytes.Equal(raw, input) {
						b.Fatal("measured snapshot reader changed complete input bytes")
					}
					observerReadSink = raw
				}
			})
		}
	}
}
