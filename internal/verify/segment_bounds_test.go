package verify

import (
	"math"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func TestSegmentCommitmentBudgetsCoreAndOwnedState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Policy, *proof.AccountSegment, *[]proof.CommitmentEvidence)
		accept bool
	}{
		{"exact boundaries", func(*Policy, *proof.AccountSegment, *[]proof.CommitmentEvidence) {}, true},
		{"commitment count", func(p *Policy, _ *proof.AccountSegment, _ *[]proof.CommitmentEvidence) { p.MaxCommitments = 1 }, false},
		{"aggregate shared flat", func(p *Policy, _ *proof.AccountSegment, _ *[]proof.CommitmentEvidence) {
			p.MaxTotalFlatEvidenceMembers = 3 // Two references to two members count as four.
		}, false},
		{"irrelevant nil proof counts", func(_ *Policy, _ *proof.AccountSegment, ev *[]proof.CommitmentEvidence) {
			*ev = append(*ev, proof.CommitmentEvidence{})
		}, false},
		{"irrelevant flat counts", func(p *Policy, _ *proof.AccountSegment, ev *[]proof.CommitmentEvidence) {
			p.MaxCommitments = 3
			*ev = append(*ev, proof.CommitmentEvidence{Flat: (*ev)[0].Flat})
		}, false},
		{"oversized later candidate", func(p *Policy, _ *proof.AccountSegment, ev *[]proof.CommitmentEvidence) {
			p.MaxCommitments, p.MaxTotalFlatEvidenceMembers = 3, 7
			bad := (*ev)[0]
			bad.Flat = &proof.FlatContentEvidence{SortedHeaders: append(slices.Clone(bad.Flat.SortedHeaders), chain.AccountHeader{})}
			*ev = append(*ev, bad)
		}, false},
		{"oversized unrelated candidate", func(p *Policy, _ *proof.AccountSegment, ev *[]proof.CommitmentEvidence) {
			p.MaxCommitments, p.MaxTotalFlatEvidenceMembers = 3, 7
			*ev = append(*ev, proof.CommitmentEvidence{Flat: &proof.FlatContentEvidence{SortedHeaders: make([]chain.AccountHeader, 3)}})
		}, false},
		{"preflight before block evaluation", func(p *Policy, s *proof.AccountSegment, _ *[]proof.CommitmentEvidence) {
			p.MaxCommitments = 1
			s.Blocks[0].BlockHash[0] ^= 1
		}, false},
		{"stale candidate before valid proof", func(p *Policy, _ *proof.AccountSegment, ev *[]proof.CommitmentEvidence) {
			p.MaxCommitments, p.MaxTotalFlatEvidenceMembers = 3, 6
			stale := (*ev)[0]
			stale.Height = 1
			*ev = append([]proof.CommitmentEvidence{stale}, (*ev)...)
		}, true},
		{"disabled limits", func(p *Policy, _ *proof.AccountSegment, _ *[]proof.CommitmentEvidence) {
			p.MaxCommitments, p.MaxFlatEvidenceMembers, p.MaxTotalFlatEvidenceMembers = 0, 0, 0
		}, true},
		{"maximum integer limits", func(p *Policy, _ *proof.AccountSegment, _ *[]proof.CommitmentEvidence) {
			p.MaxCommitments, p.MaxFlatEvidenceMembers, p.MaxTotalFlatEvidenceMembers = math.MaxInt, math.MaxInt, math.MaxInt
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, segment, commitments, _ := segmentFixture(t)
			policy := DefaultPolicy()
			policy.MaxCommitments, policy.MaxFlatEvidenceMembers, policy.MaxTotalFlatEvidenceMembers = 2, 2, 4
			tc.change(&policy, &segment, &commitments)
			path := filepath.Join(t.TempDir(), "state.json")
			if err := SaveHeaderState(path, raw); err != nil {
				t.Fatal(err)
			}
			opts := VerifyOptions{Policy: policy}
			owned, err := LoadTrustedState(path, raw.Genesis, opts)
			if err != nil {
				t.Fatal(err)
			}
			before := owned.Snapshot()
			// A caller cannot disable the owned handle's captured budgets.
			opts.Policy.MaxCommitments, opts.Policy.MaxFlatEvidenceMembers, opts.Policy.MaxTotalFlatEvidenceMembers = 0, 0, 0
			for name, result := range map[string]SegmentResult{
				"core":  VerifySegment(raw, segment, commitments, policy),
				"owned": owned.VerifySegment(segment, commitments),
			} {
				t.Run(name, func(t *testing.T) {
					if tc.accept {
						if len(result.Blocks) != len(segment.Blocks) || result.Worst() != OutcomeAccept {
							t.Fatalf("within-budget evidence did not accept: %+v", result)
						}
						for _, r := range result.Blocks {
							assertHasGuarantee(t, r.Proven, GuaranteeContentInclusion)
						}
					} else {
						if len(result.Blocks) != 1 || result.Blocks[0].Outcome != OutcomeRefused || result.Blocks[0].Reason != ReasonOversizedEvidence || result.Blocks[0].FailedAt != -1 || len(result.Blocks[0].Proven) != 0 {
							t.Fatalf("expected one preflight refusal without proven claims: %+v", result)
						}
					}
				})
			}
			if !reflect.DeepEqual(owned.Snapshot(), before) {
				t.Fatal("segment query changed owned state")
			}
		})
	}
}
