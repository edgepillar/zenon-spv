package verify

import (
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestSegmentRefusesUnsupportedOrContradictoryEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name    string
		edit    func(*chain.AccountBlock)
		outcome Outcome
		reason  ReasonCode
	}{
		{"zero version", func(b *chain.AccountBlock) { b.Version = 0 }, OutcomeRefused, ReasonUnsupportedAccountBlockVersion},
		{"future version", func(b *chain.AccountBlock) { b.Version = 2 }, OutcomeRefused, ReasonUnsupportedAccountBlockVersion},
		{"missing chain", func(b *chain.AccountBlock) { b.ChainIdentifier = 0 }, OutcomeReject, ReasonInvalidAccountBlockEnvelope},
		{"another chain", func(b *chain.AccountBlock) { b.ChainIdentifier = 99 }, OutcomeReject, ReasonChainIDMismatch},
		{"zero height", func(b *chain.AccountBlock) { b.Height = 0 }, OutcomeReject, ReasonInvalidAccountBlockEnvelope},
		{"first block has parent", func(b *chain.AccountBlock) { b.PreviousHash = chain.Hash{1} }, OutcomeReject, ReasonInvalidAccountBlockEnvelope},
		{"later block has no parent", func(b *chain.AccountBlock) { b.Height = 2 }, OutcomeReject, ReasonInvalidAccountBlockEnvelope},
		{"missing type", func(b *chain.AccountBlock) { b.BlockType = 0 }, OutcomeRefused, ReasonUnsupportedAccountBlockType},
		{"genesis type", func(b *chain.AccountBlock) { b.BlockType = chain.BlockTypeGenesisReceive }, OutcomeRefused, ReasonUnsupportedAccountBlockType},
		{"future type", func(b *chain.AccountBlock) { b.BlockType = 99 }, OutcomeRefused, ReasonUnsupportedAccountBlockType},
		{"user claims contract type", func(b *chain.AccountBlock) { b.BlockType = chain.BlockTypeContractSend }, OutcomeReject, ReasonInvalidAccountBlockEnvelope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Re-sign and commit the synthetic mutation in verified momentums.
			// This checks the envelope boundary, not signature forgery or full
			// node acceptance of these deliberately contradictory account blocks.
			state, segment, commitments, _ := segmentFixtureWithBlockEdit(t, tc.edit)
			policy := segmentFixturePolicy()
			first := state.RetainedWindow[0]
			anchor := GenesisTrustRoot{ChainID: state.Genesis.ChainID, Height: first.Height - 1, HeaderHash: first.PreviousHash}
			owned, err := NewVerifiedState(anchor, VerifyOptions{Policy: policy})
			if err != nil {
				t.Fatal(err)
			}
			verified, owned := owned.Extend(state.RetainedWindow)
			if verified.Outcome != OutcomeAccept {
				t.Fatalf("synthetic momentum chain failed: %s", verified)
			}
			for _, result := range []SegmentResult{VerifySegment(state, segment, commitments, policy), owned.VerifySegment(segment, commitments)} {
				if len(result.Blocks) != 2 || result.Blocks[0].Outcome != tc.outcome || result.Blocks[0].Reason != tc.reason || result.Blocks[0].FailedAt != 0 || len(result.Blocks[0].Proven) != 0 {
					t.Fatalf("wrong envelope outcome: %+v", result.Blocks)
				}
				if result.Blocks[1].Outcome != tc.outcome || result.Blocks[1].Reason != ReasonParentNotAccepted || result.Blocks[1].FailedAt != 1 || len(result.Blocks[1].Proven) != 0 {
					t.Fatalf("invalid parent advanced linkage: %+v", result.Blocks)
				}
			}
		})
	}
}

func TestSupportedAccountEnvelopePreservesSegmentAcceptance(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	if result := VerifySegment(state, segment, commitments, segmentFixturePolicy()); result.Worst() != OutcomeAccept {
		t.Fatalf("valid user segment failed: %v", result.Blocks)
	}
	// A segment may begin in the middle of an account chain. The nonzero
	// previous hash is a shape check; ancestry before this segment is unproven.
	segment.Blocks = segment.Blocks[1:]
	if result := VerifySegment(state, segment, commitments, segmentFixturePolicy()); result.Worst() != OutcomeAccept {
		t.Fatalf("valid partial segment failed: %v", result.Blocks)
	}
	state, segment, commitments = embeddedSegmentFixture(t)
	if result := VerifySegment(state, segment, commitments, segmentFixturePolicy()); result.Worst() != OutcomeAccept {
		t.Fatalf("valid embedded segment failed: %v", result.Blocks)
	}
}
