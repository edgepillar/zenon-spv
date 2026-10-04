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

func TestNodeCommitmentOwnedWindowMatchesLowLevel(t *testing.T) {
	c, headers, basePolicy := transitionFixture(t)
	for _, capacity := range []int{3, 6} {
		t.Run(fmt.Sprintf("K%d", capacity), func(t *testing.T) {
			policy := verify.DefaultPolicy()
			policy.W, policy.RetainHeaders = 2, capacity
			policy.ProtocolProfile = basePolicy.ProtocolProfile
			policy.MaxFlatEvidenceMembers = 4
			opts := verify.VerifyOptions{Policy: policy}
			empty, err := verify.NewVerifiedState(c.Transition.Anchor, opts)
			if err != nil {
				t.Fatal(err)
			}
			r, populated := empty.Extend(headers)
			if r.Outcome != verify.OutcomeAccept {
				t.Fatal(r)
			}
			path := filepath.Join(t.TempDir(), "state.json")
			if err := populated.Save(path); err != nil {
				t.Fatal(err)
			}
			resumed, err := verify.LoadTrustedState(path, c.Transition.Anchor, opts)
			if err != nil {
				t.Fatal(err)
			}
			for _, handle := range []struct {
				name      string
				state     verify.VerifiedState
				persisted bool
			}{{"empty", empty, false}, {"extended", populated, false}, {"resumed", resumed, true}} {
				t.Run(handle.name, func(t *testing.T) {
					before := handle.state.Snapshot()
					contextBefore, err := handle.state.VerificationContext()
					if err != nil {
						t.Fatal(err)
					}
					outcomes := make(map[verify.Outcome]bool)
					for _, v := range c.Transition.Vectors {
						if len(v.Content) != 4 {
							t.Fatal("unexpected node-derived content size")
						}
						valid := proof.CommitmentEvidence{Height: v.Header.Height, Target: v.Content[0],
							Flat: &proof.FlatContentEvidence{SortedHeaders: v.Content}}
						missing := valid
						missing.Flat = nil
						notMember := valid
						notMember.Target.Hash[0] ^= 1
						badContent := valid
						members := slices.Clone(v.Content)
						members[0].Hash[0] ^= 1
						badContent.Flat = &proof.FlatContentEvidence{SortedHeaders: members}
						oversized := valid
						oversized.Flat = &proof.FlatContentEvidence{SortedHeaders: append(slices.Clone(v.Content), v.Content[0])}
						for name, evidence := range map[string]proof.CommitmentEvidence{
							"valid": valid, "missing": missing, "not_member": notMember,
							"bad_content": badContent, "oversized": oversized,
						} {
							t.Run(fmt.Sprintf("height%d/%s", v.Header.Height, name), func(t *testing.T) {
								want := verify.VerifyCommitment(before, evidence, policy)
								if want.Outcome == verify.OutcomeAccept {
									want = want.WithTrust(verify.TrustConfiguredAnchor)
									if handle.persisted {
										want = want.WithTrust(verify.TrustPersistedState)
									}
								}
								got := handle.state.VerifyCommitment(evidence)
								if !reflect.DeepEqual(got, want) {
									t.Fatalf("owned query changed outcome, reason, guarantees or trust: got=%+v want=%+v", got, want)
								}
								outcomes[got.Outcome] = true
								assertBoundedGuarantees(t, got)
							})
						}
					}
					if handle.name != "empty" && (!outcomes[verify.OutcomeAccept] || !outcomes[verify.OutcomeReject] || !outcomes[verify.OutcomeRefused]) {
						t.Fatal("comparison did not exercise all three outcomes")
					}
					contextAfter, err := handle.state.VerificationContext()
					if err != nil || !reflect.DeepEqual(contextBefore, contextAfter) || !reflect.DeepEqual(before, handle.state.Snapshot()) {
						t.Fatal("queries changed the captured context or retained state", err)
					}
				})
			}
		})
	}
}

func TestNodeCommitmentLowLevelChecksUnqueriedRetainedHeaders(t *testing.T) {
	c, headers, policy := transitionFixture(t)
	policy.W, policy.RetainHeaders = 2, len(headers)
	initial, err := verify.NewVerifiedState(c.Transition.Anchor, verify.VerifyOptions{Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	r, owned := initial.Extend(headers)
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	v := c.Transition.Vectors[0]
	evidence := proof.CommitmentEvidence{Height: v.Header.Height, Target: v.Content[0],
		Flat: &proof.FlatContentEvidence{SortedHeaders: v.Content}}
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
			got := verify.VerifyCommitment(callerOwned, evidence, policy)
			if got.Outcome != tc.outcome || got.Reason != tc.reason || len(got.Proven) != 0 {
				t.Fatal("low-level query skipped validation outside the selected height", got)
			}
			if got := owned.VerifyCommitment(evidence); got.Outcome != verify.OutcomeAccept {
				t.Fatal("caller-owned snapshot mutation changed the immutable handle", got)
			}
		})
	}
}
