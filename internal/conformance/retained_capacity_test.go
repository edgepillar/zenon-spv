package conformance_test

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type retainedWorkload struct {
	anchor   verify.GenesisTrustRoot
	opts     verify.VerifyOptions
	state    verify.VerifiedState
	next     chain.Header
	evidence proof.CommitmentEvidence
	path     string
	bytes    int64
}

// Synthetic load generation uses SPV hash functions for stress measurements.
// It is deliberately separate from the independently node-derived corpus and
// is not conformance, executed-ledger or public-network performance evidence.
func newRetainedWorkload(t testing.TB, capacity int) retainedWorkload {
	return newRetainedContentWorkload(t, capacity, 99, nil)
}

func newRetainedContentWorkload(t testing.TB, capacity int, chainID uint64, content []chain.AccountHeader) retainedWorkload {
	t.Helper()
	w := retainedWorkload{anchor: verify.GenesisTrustRoot{ChainID: chainID, Height: 10000, HeaderHash: chain.Hash{1}}}
	w.opts.Policy = verify.DefaultPolicy()
	w.opts.Policy.RetainHeaders = capacity
	w.opts.Policy.ProtocolProfile = &verify.ProtocolProfile{Version: 1, Anchor: w.anchor,
		V2FromHeight: 10001, ValidThrough: 10001 + uint64(capacity), Source: "synthetic capacity workload"}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // Public test seed.
	pub := key.Public().(ed25519.PublicKey)
	member := chain.AccountHeader{Address: chain.PubKeyToAddress(pub), Height: 1, Hash: chain.Hash{2}}
	if content == nil {
		content = []chain.AccountHeader{member}
	}
	w.evidence = proof.CommitmentEvidence{Height: 10001, Target: content[0], Flat: &proof.FlatContentEvidence{SortedHeaders: content}}
	previous := w.anchor.HeaderHash
	headers := make([]chain.Header, capacity+1)
	entries := make([]verify.ProducerEntry, len(headers))
	for i := range headers {
		h := chain.Header{Version: 2, ChainIdentifier: w.anchor.ChainID, Height: 10001 + uint64(i),
			PreviousHash: previous, TimestampUnix: 1700000000 + uint64(i)*10, DataHash: chain.Hash{3},
			ContentHash: chain.MomentumContentHash(content), ChangesHash: chain.Hash{4},
			NextFusionPrice: 1000, NextWorkPrice: 1000, PublicKey: pub}
		h.HeaderHash = h.ComputeHash()
		h.Signature = ed25519.Sign(key, h.HeaderHash[:])
		headers[i], previous = h, h.HeaderHash
		entries[i] = verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: member.Address}
	}
	w.next = headers[capacity]
	schedule, err := verify.NewProducerSchedule(w.anchor.ChainID,
		[]verify.ProducerCoverage{{FromHeight: 10001, ThroughHeight: w.next.Height}}, entries, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.opts.ProducerAuth = verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired, Authorizer: verify.NewScheduleAuthorizer(schedule)}
	w.state, err = verify.NewVerifiedState(w.anchor, w.opts)
	if err != nil {
		t.Fatal(err)
	}
	result, state := w.state.Extend(headers[:capacity])
	if result.Outcome != verify.OutcomeAccept {
		t.Fatal("capacity workload failed to populate retained state", result)
	}
	w.state = state
	w.path = filepath.Join(t.TempDir(), "state.json")
	if err := w.state.Save(w.path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(w.path)
	if err != nil {
		t.Fatal(err)
	}
	w.bytes = info.Size()
	return w
}

func TestRetainedCapacityWorkloads(t *testing.T) {
	for _, capacity := range []int{16, 256, verify.MaxRetainHeaders} {
		t.Run(fmt.Sprintf("K%d", capacity), func(t *testing.T) {
			w := newRetainedWorkload(t, capacity)
			if r := w.state.VerifyCommitment(w.evidence); r.Outcome != verify.OutcomeAccept {
				t.Fatal(r)
			}
			r, next := w.state.Extend([]chain.Header{w.next})
			summary, err := next.RetainedSummary()
			if r.Outcome != verify.OutcomeAccept || err != nil || summary.Count != capacity || summary.Capacity != capacity ||
				summary.Tip.Height != w.next.Height || summary.Oldest.Height != 10002 || summary.DepthEligible.ThroughHeight != w.next.Height-6 {
				t.Fatal("full-capacity extension broke count, eviction or depth", r, err)
			}
			if r := next.VerifyCommitment(w.evidence); r.Outcome != verify.OutcomeRefused || r.Reason != verify.ReasonHeightOutOfWindow {
				t.Fatal("full-capacity extension kept an evicted target", r)
			}
			if r := w.state.VerifyCommitment(w.evidence); r.Outcome != verify.OutcomeAccept {
				t.Fatal("extension changed the immutable predecessor", r)
			}
			if err := next.Save(w.path); err != nil {
				t.Fatal(err)
			}
			loaded, err := verify.LoadTrustedState(w.path, w.anchor, w.opts)
			if err != nil {
				t.Fatal(err)
			}
			loadedSummary, err := loaded.RetainedSummary()
			if err != nil || loadedSummary.Count != capacity || *loadedSummary.Tip != *summary.Tip || *loadedSummary.Oldest != *summary.Oldest {
				t.Fatal("full-capacity resume changed the retained range", err)
			}
			candidate := w.evidence
			candidate.Height++
			if r := loaded.VerifyCommitment(candidate); r.Outcome != verify.OutcomeAccept || !slices.Contains(r.TrustAssumptions, verify.TrustPersistedState) {
				t.Fatal("full-capacity resume lost inclusion or provenance", r)
			}
		})
	}
}

// Each operation starts from a fixed full window. Setup and file creation are
// outside timing; successful-result checks are measured. Resume reads are warm
// filesystem reads, while Save includes validation, atomic replacement and the
// platform's sync behavior. Allocation volume is not peak resident memory.
func BenchmarkRetainedCapacity(b *testing.B) {
	corpus := loadNodeAccountCorpus(b, "delayed-inclusion.json")
	for _, capacity := range []int{16, 256, verify.MaxRetainHeaders} {
		b.Run(fmt.Sprintf("K%d", capacity), func(b *testing.B) {
			w := newRetainedWorkload(b, capacity)
			for _, name := range []string{"ExtendOne", "CommitmentFlat", "TrustedResume", "Save"} {
				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						switch name {
						case "ExtendOne":
							r, next := w.state.Extend([]chain.Header{w.next})
							summary, err := next.RetainedSummary()
							if r.Outcome != verify.OutcomeAccept || err != nil || summary.Count != capacity || summary.Tip.Height != w.next.Height || summary.Oldest.Height != 10002 {
								b.Fatal("benchmark entered a failed full-window extension path")
							}
						case "CommitmentFlat":
							r := w.state.VerifyCommitment(w.evidence)
							if r.Outcome != verify.OutcomeAccept || !slices.Contains(r.Proven, verify.GuaranteeContentInclusion) {
								b.Fatal("benchmark entered a failed retained inclusion path")
							}
						case "TrustedResume":
							loaded, err := verify.LoadTrustedState(w.path, w.anchor, w.opts)
							if err != nil {
								b.Fatal("benchmark entered a failed full-window resume path")
							}
							summary, err := loaded.RetainedSummary()
							if err != nil || summary.Count != capacity || summary.Tip.Height != w.next.Height-1 {
								b.Fatal("benchmark resumed a different retained workload")
							}
						case "Save":
							if err := w.state.Save(w.path); err != nil {
								b.Fatal("benchmark entered a failed full-window save path")
							}
						}
					}
					b.ReportMetric(float64(capacity), "retained-headers")
					b.ReportMetric(float64(w.bytes), "state-B")
				})
			}
			// Account envelopes come from the pinned node corpus, but the full
			// window and confirming momentum are synthetic stress inputs. These
			// operations are local resource measurements, not network evidence.
			for _, vectors := range corpus.Segments {
				name := "SegmentUser"
				if vectors.Address.IsEmbeddedAddress() {
					name = "SegmentEmbedded"
				}
				b.Run(name, func(b *testing.B) {
					segment := proof.AccountSegment{Address: vectors.Address}
					var content []chain.AccountHeader
					for _, v := range vectors.Vectors {
						segment.Blocks = append(segment.Blocks, v.Block)
						content = append(content, v.Block.AccountHeader())
					}
					workload := newRetainedContentWorkload(b, capacity, corpus.Chain.Anchor.ChainID, content)
					commitments := make([]proof.CommitmentEvidence, len(content))
					for i, target := range content {
						commitments[i] = workload.evidence
						commitments[i].Target = target
					}
					b.ReportAllocs()
					for b.Loop() {
						r := workload.state.VerifySegment(segment, commitments)
						if len(r.Blocks) != 3 {
							b.Fatal("benchmark lost its three-block segment")
						}
						for _, row := range r.Blocks {
							if row.Outcome != verify.OutcomeAccept || !slices.Contains(row.Proven, verify.GuaranteeContentInclusion) {
								b.Fatal("benchmark entered a failed retained segment path", row)
							}
						}
					}
					b.ReportMetric(float64(capacity), "retained-headers")
					b.ReportMetric(3, "blocks/op")
				})
			}
		})
	}
}
