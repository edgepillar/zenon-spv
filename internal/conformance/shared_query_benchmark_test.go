package conformance_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Measure shared read-only queries, including exact result checks and parallel
// loop overhead. Concurrent ns/op is group wall time divided by queries, not
// individual request latency. Construction and preservation checks are untimed.
func BenchmarkSharedImmutableQueries(b *testing.B) {
	corpus := loadNodeAccountCorpus(b, "delayed-inclusion.json")
	flat := newFlatWorkload(b, 1000, 1)
	for _, capacity := range []int{256, verify.MaxRetainHeaders} {
		b.Run(fmt.Sprintf("K%d", capacity), func(b *testing.B) {
			cell := func(name string, w retainedWorkload, input any, check func() bool) {
				b.Run(name, func(b *testing.B) {
					beforeState := w.state.Snapshot()
					beforeContext, err := w.state.VerificationContext()
					if err != nil || !check() {
						b.Fatal("shared query benchmark setup failed")
					}
					beforeInput, err := json.Marshal(input)
					if err != nil {
						b.Fatal("shared query benchmark input capture failed")
					}
					var failed atomic.Bool
					b.SetParallelism(1)
					b.ReportAllocs()
					b.ResetTimer()
					b.RunParallel(func(pb *testing.PB) {
						for pb.Next() {
							if !check() {
								failed.Store(true)
							}
						}
					})
					b.StopTimer()
					afterContext, err := w.state.VerificationContext()
					afterInput, inputErr := json.Marshal(input)
					if failed.Load() || err != nil || inputErr != nil ||
						!reflect.DeepEqual(w.state.Snapshot(), beforeState) ||
						!reflect.DeepEqual(afterContext, beforeContext) || !bytes.Equal(afterInput, beforeInput) {
						b.Fatal("shared query benchmark changed results, state, context or caller input")
					}
					b.ReportMetric(float64(capacity), "retained-headers")
					b.ReportMetric(float64(runtime.GOMAXPROCS(0)), "workers")
				})
			}
			for _, members := range []int{1, 1000} {
				var content []chain.AccountHeader
				if members == 1000 {
					content = flat.bundle.Commitments[0].Flat.SortedHeaders
				}
				w := newRetainedContentWorkload(b, capacity, 99, content)
				want := w.state.VerifyCommitment(w.evidence)
				if want.Outcome != verify.OutcomeAccept || !slices.Contains(want.Proven, verify.GuaranteeContentInclusion) {
					b.Fatal("shared commitment benchmark reference failed")
				}
				cell(fmt.Sprintf("CommitmentM%d", members), w, w.evidence, func() bool {
					return sameSharedQueryResult(w.state.VerifyCommitment(w.evidence), want)
				})
			}
			for _, vectors := range corpus.Segments {
				name := "SegmentUser"
				if vectors.Address.IsEmbeddedAddress() {
					name = "SegmentEmbedded"
				}
				segment := proof.AccountSegment{Address: vectors.Address}
				var content []chain.AccountHeader
				for _, vector := range vectors.Vectors {
					segment.Blocks = append(segment.Blocks, vector.Block)
					content = append(content, vector.Block.AccountHeader())
				}
				w := newRetainedContentWorkload(b, capacity, corpus.Chain.Anchor.ChainID, content)
				commitments := make([]proof.CommitmentEvidence, len(content))
				for i, target := range content {
					commitments[i] = w.evidence
					commitments[i].Target = target
				}
				want := w.state.VerifySegment(segment, commitments)
				if len(want.Blocks) != 3 || want.Worst() != verify.OutcomeAccept {
					b.Fatal("shared segment benchmark reference failed")
				}
				input := struct {
					Segment     proof.AccountSegment
					Commitments []proof.CommitmentEvidence
				}{segment, commitments}
				cell(name, w, input, func() bool {
					got := w.state.VerifySegment(segment, commitments)
					if len(got.Blocks) != len(want.Blocks) {
						return false
					}
					for i := range got.Blocks {
						if !sameSharedQueryResult(got.Blocks[i], want.Blocks[i]) {
							return false
						}
					}
					return true
				})
			}
		})
	}
}

func sameSharedQueryResult(a, b verify.Result) bool {
	return a.Outcome == b.Outcome && a.Reason == b.Reason && a.Message == b.Message && a.FailedAt == b.FailedAt &&
		(a.Proven == nil) == (b.Proven == nil) && slices.Equal(a.Proven, b.Proven) &&
		(a.NotProven == nil) == (b.NotProven == nil) && slices.Equal(a.NotProven, b.NotProven) &&
		(a.TrustAssumptions == nil) == (b.TrustAssumptions == nil) && slices.Equal(a.TrustAssumptions, b.TrustAssumptions)
}
