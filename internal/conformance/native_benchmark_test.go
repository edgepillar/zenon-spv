package conformance_test

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// BenchmarkNativeClient measures fixed, source-pinned local workloads. Fixture
// loading, state construction, schedule generation, and file creation stay
// outside B.Loop; per-operation verification and result checks stay inside.
// These measurements are not public-network throughput or finality evidence.
func BenchmarkNativeClient(b *testing.B) {
	c := loadNodeAccountCorpus(b, "contract-batches.json")
	if len(c.Segments) != 1 || len(c.Segments[0].Vectors) != 5 || len(c.Batches) != 2 {
		b.Fatal("benchmark requires the complete pinned contract batch corpus")
	}
	var headers []chain.Header
	var evidence []proof.CommitmentEvidence
	var entries []verify.ProducerEntry
	for _, v := range c.Chain.Vectors {
		headers = append(headers, v.Header)
		entries = append(entries, verify.ProducerEntry{Height: v.Header.Height, TimestampUnix: v.Header.TimestampUnix,
			ProducingAddr: chain.PubKeyToAddress(v.Header.PublicKey)})
		for _, target := range v.Content {
			evidence = append(evidence, proof.CommitmentEvidence{Height: v.Header.Height, Target: target,
				Flat: &proof.FlatContentEvidence{SortedHeaders: v.Content}})
		}
	}
	segment := proof.AccountSegment{Address: c.Segments[0].Address}
	for _, v := range c.Segments[0].Vectors {
		segment.Blocks = append(segment.Blocks, v.Block)
	}
	if len(evidence) != 5 || headers[0].Height != 4001 || headers[8].Height != 4009 {
		b.Fatal("benchmark workload changed; review its declared operation sizes")
	}
	opts := verify.VerifyOptions{Policy: verify.DefaultPolicy()}
	initial, err := verify.NewVerifiedState(c.Chain.Anchor, opts)
	if err != nil {
		b.Fatal(err)
	}
	r, state := initial.Extend(headers)
	if r.Outcome != verify.OutcomeAccept {
		b.Fatal(r)
	}
	coverage := []verify.ProducerCoverage{{FromHeight: 4001, ThroughHeight: 4009}}
	schedule, err := verify.NewProducerSchedule(c.Chain.Anchor.ChainID, coverage, entries, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	authorized := opts
	authorized.ProducerAuth = verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired, Authorizer: verify.NewScheduleAuthorizer(schedule)}
	for _, tc := range []struct {
		name string
		opts verify.VerifyOptions
	}{
		{"HeadersV1/claimed_key", opts},
		{"HeadersV1/operator_schedule", authorized},
	} {
		b.Run(tc.name, func(b *testing.B) {
			base, err := verify.NewVerifiedState(c.Chain.Anchor, tc.opts)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				result, next := base.Extend(headers)
				if result.Outcome != verify.OutcomeAccept || next.Empty() {
					b.Fatal("benchmark entered a failed header-verification path")
				}
			}
			b.ReportMetric(float64(len(headers)), "headers/op")
		})
	}
	b.Run("HeadersV1V2/operator_profile", func(b *testing.B) {
		corpus := loadCorpus(b)
		series := corpus.Transition
		var transition []chain.Header
		for _, v := range series.Vectors {
			transition = append(transition, v.Header)
		}
		policy := verify.DefaultPolicy()
		policy.W = 5
		policy.ProtocolProfile = &verify.ProtocolProfile{Version: 1, Anchor: series.Anchor,
			V2FromHeight: series.V2FromHeight, ValidThrough: transition[5].Height, Source: "pinned benchmark fixture"}
		base, err := verify.NewVerifiedState(series.Anchor, verify.VerifyOptions{Policy: policy})
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			result, next := base.Extend(transition)
			if result.Outcome != verify.OutcomeAccept || next.Empty() {
				b.Fatal("benchmark entered a failed activation-profile path")
			}
		}
		b.ReportMetric(float64(len(transition)), "headers/op")
	})
	b.Run("CommitmentFlat", func(b *testing.B) {
		candidate := evidence[0]
		b.ReportAllocs()
		for b.Loop() {
			result := state.VerifyCommitment(candidate)
			if result.Outcome != verify.OutcomeAccept || !slices.Contains(result.Proven, verify.GuaranteeContentInclusion) {
				b.Fatal("benchmark entered a failed inclusion path")
			}
		}
		b.ReportMetric(float64(len(candidate.Flat.SortedHeaders)), "members/op")
	})
	b.Run("ContractSegment", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			result := state.VerifySegment(segment, evidence)
			if len(result.Blocks) != 5 {
				b.Fatal("benchmark lost contract children or receives")
			}
			for _, block := range result.Blocks {
				if block.Outcome != verify.OutcomeAccept || !slices.Contains(block.Proven, verify.GuaranteeContentInclusion) {
					b.Fatal("benchmark entered a failed segment path")
				}
			}
		}
		b.ReportMetric(float64(len(segment.Blocks)), "blocks/op")
	})
	b.Run("TrustedResume/operator_schedule", func(b *testing.B) {
		path := filepath.Join(b.TempDir(), "state.json")
		if err := state.Save(path); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			loaded, err := verify.LoadTrustedState(path, c.Chain.Anchor, authorized)
			if err != nil || loaded.Empty() {
				b.Fatal("benchmark entered a failed trusted-resume path")
			}
		}
		b.ReportMetric(7, "headers/op")
	})
	b.Run("RetainedSummary", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			summary, err := state.RetainedSummary()
			if err != nil || summary.Count != 7 || summary.Tip.Height != 4009 || summary.DepthEligible == nil || summary.DepthEligible.ThroughHeight != 4003 {
				b.Fatal("benchmark entered a failed summary path")
			}
		}
	})
	b.Run("VerificationContext", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			context, err := state.VerificationContext()
			if err != nil || context.Fingerprint == nil || context.Anchor != c.Chain.Anchor {
				b.Fatal("benchmark entered a failed configuration-context path")
			}
		}
	})
}
