package conformance_test

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Include unsorted inputs when evaluating hash allocation changes. Every
// ordering must match the same independently node-derived content root.
func BenchmarkContentHashOrdering(b *testing.B) {
	for _, size := range []int{1000, 100000} {
		b.Run(fmt.Sprintf("M%d", size), func(b *testing.B) {
			w := newFlatWorkload(b, size, 1)
			for _, order := range []string{"Sorted", "Reversed", "Shuffled"} {
				b.Run(order, func(b *testing.B) {
					headers := slices.Clone(w.bundle.Commitments[0].Flat.SortedHeaders)
					switch order {
					case "Reversed":
						slices.Reverse(headers)
					case "Shuffled":
						rng := rand.New(rand.NewPCG(1, 2))
						rng.Shuffle(len(headers), func(i, j int) { headers[i], headers[j] = headers[j], headers[i] })
					}
					before := slices.Clone(headers)
					b.ReportAllocs()
					for b.Loop() {
						if chain.MomentumContentHash(headers) != w.sample.Headers[0].ContentHash {
							b.Fatal("ordered workload changed the independently pinned root")
						}
					}
					if !slices.Equal(headers, before) {
						b.Fatal("content hashing changed the measured ordering")
					}
					b.ReportMetric(float64(size), "members/op")
				})
			}
		})
	}
}
