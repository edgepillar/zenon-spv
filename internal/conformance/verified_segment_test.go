package conformance_test

import (
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestNodeSegmentOwnedWindowMatchesLowLevel(t *testing.T) {
	c, bundle := delayedInclusionBundle(t)
	opts, _ := delayedOptions(t, c)
	opts.Policy.MaxSegmentBlocks, opts.Policy.MaxFlatEvidenceMembers = 3, 2
	empty, err := verify.NewVerifiedState(c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	type queryHandle struct {
		name      string
		state     verify.VerifiedState
		persisted bool
	}
	handles := []queryHandle{{"empty", empty, false}}
	for _, count := range []int{16, 18, 19} {
		r, state := empty.Extend(bundle.Headers[:count])
		if r.Outcome != verify.OutcomeAccept {
			t.Fatal(r)
		}
		handles = append(handles, queryHandle{fmt.Sprintf("tip%d", 5000+count), state, false})
		if count == 18 {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := state.Save(path); err != nil {
				t.Fatal(err)
			}
			state, err = verify.LoadTrustedState(path, c.Chain.Anchor, opts)
			if err != nil {
				t.Fatal(err)
			}
			handles = append(handles, queryHandle{"resumed", state, true})
		}
	}
	for _, handle := range handles {
		t.Run(handle.name, func(t *testing.T) {
			before := handle.state.Snapshot()
			contextBefore, err := handle.state.VerificationContext()
			if err != nil {
				t.Fatal(err)
			}
			outcomes := make(map[verify.Outcome]bool)
			for _, original := range bundle.Segments {
				kind := "user"
				if original.Address.IsEmbeddedAddress() {
					kind = "embedded"
				}
				for _, name := range []string{"valid", "suffix", "empty", "oversized_segment", "missing", "missing_flat", "bad_content", "wrong_height", "stale_then_valid", "bad_then_valid", "oversized_unused", "bad_block", "bad_first_block"} {
					t.Run(kind+"/"+name, func(t *testing.T) {
						segment := original
						segment.Blocks = slices.Clone(original.Blocks)
						commitments := slices.Clone(bundle.Commitments)
						first := -1
						for i, evidence := range commitments {
							if evidence.Target == segment.Blocks[0].AccountHeader() {
								first = i
								break
							}
						}
						if first < 0 {
							t.Fatal("node corpus lost the selected segment's first commitment")
						}
						bad := commitments[first]
						members := slices.Clone(bad.Flat.SortedHeaders)
						members[0].Hash[0] ^= 1
						bad.Flat = &proof.FlatContentEvidence{SortedHeaders: members}
						switch name {
						case "suffix":
							segment.Blocks = segment.Blocks[1:]
						case "empty":
							segment.Blocks = nil
						case "oversized_segment":
							segment.Blocks = append(segment.Blocks, segment.Blocks[0])
						case "missing":
							commitments = slices.Delete(commitments, first, first+1)
						case "missing_flat":
							commitments[first].Flat = nil
						case "bad_content":
							commitments[first] = bad
						case "wrong_height":
							commitments[first].Height = 5007
						case "stale_then_valid":
							stale := commitments[first]
							stale.Height = 5020
							commitments = append([]proof.CommitmentEvidence{stale}, commitments...)
						case "bad_then_valid":
							commitments = append([]proof.CommitmentEvidence{bad}, commitments...)
						case "oversized_unused":
							unused := commitments[first]
							unused.Target.Hash[0] ^= 1
							unused.Flat = &proof.FlatContentEvidence{SortedHeaders: append(slices.Clone(unused.Flat.SortedHeaders), unused.Target)}
							commitments = append(commitments, unused)
						case "bad_block":
							segment.Blocks[1].BlockHash[0] ^= 1
						case "bad_first_block":
							segment.Blocks[0].BlockHash[0] ^= 1
						}
						want := verify.VerifySegment(before, segment, commitments, opts.Policy)
						for i, row := range want.Blocks {
							if row.Outcome == verify.OutcomeAccept {
								row = row.WithTrust(verify.TrustConfiguredAnchor)
								if handle.persisted {
									row = row.WithTrust(verify.TrustPersistedState)
								}
								row = row.WithTrust(verify.TrustExternalProducerSchedule)
								want.Blocks[i] = row
							}
						}
						got := handle.state.VerifySegment(segment, commitments)
						if !reflect.DeepEqual(got, want) {
							t.Fatalf("owned segment changed results, reasons, guarantees or trust: got=%+v want=%+v", got, want)
						}
						for _, row := range got.Blocks {
							outcomes[row.Outcome] = true
							assertBoundedGuarantees(t, row)
						}
					})
				}
			}
			if handle.name != "empty" && (!outcomes[verify.OutcomeAccept] || !outcomes[verify.OutcomeReject] || !outcomes[verify.OutcomeRefused]) {
				t.Fatal("comparison did not exercise all three outcomes")
			}
			contextAfter, err := handle.state.VerificationContext()
			if err != nil || !reflect.DeepEqual(contextBefore, contextAfter) || !reflect.DeepEqual(before, handle.state.Snapshot()) {
				t.Fatal("queries changed captured context or retained state", err)
			}
		})
	}
}

func TestNodeSegmentLowLevelChecksUnqueriedRetainedHeaders(t *testing.T) {
	c, bundle := delayedInclusionBundle(t)
	opts, _ := delayedOptions(t, c)
	initial, err := verify.NewVerifiedState(c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	r, owned := initial.Extend(bundle.Headers[:18])
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	for _, tc := range []struct {
		name    string
		edit    func(*chain.Header)
		outcome verify.Outcome
		reason  verify.ReasonCode
	}{
		{"unsupported_version", func(h *chain.Header) { h.Version = 3 }, verify.OutcomeRefused, verify.ReasonUnsupportedHeaderVersion},
		{"invalid_v2_price", func(h *chain.Header) { h.NextWorkPrice = 999 }, verify.OutcomeReject, verify.ReasonInvalidResourcePrice},
	} {
		t.Run(tc.name, func(t *testing.T) {
			callerOwned := owned.Snapshot()
			tc.edit(&callerOwned.RetainedWindow[len(callerOwned.RetainedWindow)-1])
			for _, segment := range bundle.Segments {
				got := verify.VerifySegment(callerOwned, segment, bundle.Commitments, opts.Policy)
				if got.Blocks[0].Outcome != tc.outcome || got.Blocks[0].Reason != tc.reason || len(got.Blocks[0].Proven) != 0 {
					t.Fatal("low-level segment skipped an unqueried retained header", got)
				}
				for _, row := range owned.VerifySegment(segment, bundle.Commitments).Blocks {
					if row.Outcome != verify.OutcomeAccept {
						t.Fatal("snapshot mutation changed the immutable handle", row)
					}
				}
			}
		})
	}
}
