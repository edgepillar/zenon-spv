package verify

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/0x3639/zenon-spv/internal/proof"
)

func TestSegmentRejectsAmountAliasesWithoutResigning(t *testing.T) {
	for _, mutation := range []string{"negative", "truncated overflow"} {
		t.Run(mutation, func(t *testing.T) {
			state, segment, commitments, _ := segmentFixture(t)
			policy := Policy{W: WindowLow}
			if got := VerifySegment(state, segment, commitments, policy); got.Worst() != OutcomeAccept {
				t.Fatalf("baseline: %v", got)
			}
			amount := new(big.Int).Set(segment.Blocks[0].Amount)
			if mutation == "negative" {
				amount.Neg(amount)
			} else {
				amount.Add(amount, new(big.Int).Lsh(big.NewInt(1), 256))
			}
			segment.Blocks[0].Amount = amount
			// Exercise the offline bundle path. The original hash, signature,
			// commitments, and second block are unchanged.
			raw, err := json.Marshal(proof.HeaderBundle{Version: proof.WireVersion, Segments: []proof.AccountSegment{segment}})
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := proof.UnmarshalHeaderBundleJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
			got := VerifySegment(state, bundle.Segments[0], commitments, policy)
			if got.Worst() != OutcomeReject || got.Blocks[0].Reason != ReasonInvalidAmount || got.Blocks[0].FailedAt != 0 || got.Blocks[1].Reason != ReasonParentNotAccepted || got.Blocks[1].Outcome != OutcomeReject {
				t.Fatalf("changed amount accepted without resigning: %+v", got.Blocks)
			}
		})
	}
}

func TestInvalidAmountReasonName(t *testing.T) {
	if ReasonInvalidAmount.String() != "ReasonInvalidAmount" {
		t.Fatal("unstable amount diagnostic")
	}
}

func TestSegmentAmountBoundaryWithSignedCommitments(t *testing.T) {
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))
	for _, amount := range []*big.Int{nil, new(big.Int), max, new(big.Int).Add(max, big.NewInt(1)), big.NewInt(-1)} {
		state, segment, commitments, _ := segmentFixtureWithAmount(t, amount)
		result := VerifySegment(state, segment, commitments, Policy{W: WindowLow})
		valid := amount == nil || (amount.Sign() >= 0 && amount.BitLen() <= 255)
		if valid && result.Worst() != OutcomeAccept {
			t.Fatalf("valid signed boundary failed: %v", result.Blocks)
		}
		if !valid && (result.Worst() != OutcomeReject || result.Blocks[0].Reason != ReasonInvalidAmount || result.Blocks[1].Reason != ReasonParentNotAccepted) {
			t.Fatalf("invalid signed scalar accepted: %v", result.Blocks)
		}
	}
}
