package main

import (
	"reflect"
	"testing"
)

func BenchmarkConsumerShapeSpans(b *testing.B) {
	for _, item := range consumerShapeWorkloads(b) {
		var want queryReport
		if referenceShapeDecode(item.raw, &want) != item.accepted {
			b.Fatal("previous decoder disagrees with the selected shape workload")
		}
		for _, mode := range []string{"previous", "borrowed"} {
			b.Run(item.name+"/"+mode, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(item.raw)))
				for b.Loop() {
					var got queryReport
					var ok bool
					if mode == "previous" {
						ok = referenceShapeDecode(item.raw, &got)
					} else {
						ok = decodeExact(item.raw, &got)
					}
					if ok != item.accepted || !reflect.DeepEqual(got, want) {
						b.Fatal("measured shape decoder changed its selected result")
					}
					if ok && (!validReport(got) || matchReport(got, item.expected) != "") {
						b.Fatal("measured complete report failed independently selected matching")
					}
					consumerTokenSink = ok
				}
			})
		}
	}
}
