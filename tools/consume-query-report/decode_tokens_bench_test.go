package main

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

var consumerTokenSink bool

func BenchmarkConsumerTokenPrefilter(b *testing.B) {
	r, expected := matchingInputs(b)
	workloads := []struct {
		name     string
		raw      []byte
		accepted bool
	}{{"valid_report", encode(b, r), true}, {"valid_escaped_limit", caveatInput(b, strings.Repeat(`\u0078`, 4096)), true}}
	for _, size := range []int{32768, 1 << 20, 3 << 20} {
		for _, field := range []string{"string", "integer"} {
			workloads = append(workloads, struct {
				name     string
				raw      []byte
				accepted bool
			}{field + "_" + strconv.Itoa(size), oversizedConsumerInput(b, field, size), false})
		}
	}
	for _, workload := range workloads {
		var want queryReport
		if referenceConsumerDecode(workload.raw, &want) != workload.accepted {
			b.Fatal("reference workload decision differs from selection")
		}
		for _, mode := range []string{"previous", "prefilter"} {
			b.Run(workload.name+"/"+mode, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var got queryReport
					var ok bool
					if mode == "previous" {
						ok = referenceConsumerDecode(workload.raw, &got)
					} else {
						ok = decodeExact(workload.raw, &got)
					}
					if ok != workload.accepted || !reflect.DeepEqual(got, want) {
						b.Fatal("measured decoder changed its selected result")
					}
					if ok && (!validReport(got) || matchReport(got, expected) != "") {
						b.Fatal("valid decoder workload failed independently selected matching")
					}
					consumerTokenSink = ok
				}
			})
		}
	}
}
