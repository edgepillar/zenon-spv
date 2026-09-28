package conformance_test

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestNodeTransitionThroughVerifiedStateAPI(t *testing.T) {
	c, headers, policy := transitionFixture(t)
	policy.W = 2
	opts := verify.VerifyOptions{Policy: policy}
	state, err := verify.NewVerifiedState(c.Transition.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	r, before := state.Extend(headers[:2])
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := before.Save(path); err != nil {
		t.Fatal(err)
	}
	resumed, err := verify.LoadTrustedState(path, c.Transition.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	r, after := resumed.Extend(headers[2:])
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	v := c.Transition.Vectors[3]
	r = after.VerifyCommitment(proof.CommitmentEvidence{Height: v.Header.Height, Target: v.Content[0],
		Flat: &proof.FlatContentEvidence{SortedHeaders: v.Content}})
	if r.Outcome != verify.OutcomeAccept || !slices.Contains(r.Proven, verify.GuaranteeContentInclusion) {
		t.Fatal(r)
	}
	for _, tag := range []verify.TrustAssumption{verify.TrustConfiguredAnchor, verify.TrustPersistedState, verify.TrustExternalProtocolProfile} {
		if !slices.Contains(r.TrustAssumptions, tag) {
			t.Errorf("missing captured trust input %s", tag)
		}
	}
	if err := after.Save(path); err != nil {
		t.Fatal(err)
	}
	opts.Policy.ProtocolProfile = nil
	if _, err := verify.LoadTrustedState(path, c.Transition.Anchor, opts); !errors.Is(err, verify.ErrProtocolProfileMismatch) {
		t.Fatalf("resume silently dropped the activation profile: %v", err)
	}
	if tip, _ := before.Tip(); tip.Height != 2002 {
		t.Fatal("later verification changed the earlier handle")
	}
}
