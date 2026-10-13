package conformance_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Select conversion outcomes by signed input profiles, never by node MATCH.
// The store-only profiles all carry the unchanged original receive bytes.
func accountReceiveRPCError(t *testing.T, profile string) error {
	t.Helper()
	switch profile {
	case "receive-amount-nonzero", "receive-token-nonzero", "receive-to-nonzero", "receive-source-zero":
		return fetch.ErrHashMismatch
	case "exact", "source-header-missing", "source-body-missing", "source-header-corrupt", "source-body-corrupt",
		"source-index-other-original", "confirmation-missing", "confirmation-before", "confirmation-after",
		"receiver-before-enforcement", "receiver-at-enforcement", "receiver-after-enforcement",
		"received", "received-empty", "ack-missing", "ack-wrong", "ack-corrupt", "previous-ack-after":
		return nil
	default:
		t.Fatal("unselected receive input profile")
		return nil
	}
}

func accountReceiveRPCState(t *testing.T) (verify.VerifiedState, proof.HeaderBundle) {
	t.Helper()
	anchor, bundle := nodeAccountBundle(t)
	initial, err := verify.NewVerifiedState(anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	result, state := initial.Extend(bundle.Headers)
	if result.Outcome != verify.OutcomeAccept {
		t.Fatal(result)
	}
	return state, bundle
}

func assertReceiveRPCInclusion(t *testing.T, result verify.SegmentResult, want int) {
	t.Helper()
	if len(result.Blocks) != want || result.Worst() != verify.OutcomeAccept {
		t.Fatal("converted original blocks did not retain their selected inclusion/signature result")
	}
	for _, block := range result.Blocks {
		if !slices.Contains(block.Proven, verify.GuaranteeContentInclusion) ||
			!slices.Contains(block.Proven, verify.GuaranteeSignatureAuthenticity) ||
			!slices.Contains(block.NotProven, verify.GuaranteeStateTransition) {
			t.Fatal("RPC conversion inflated the bounded inclusion/signature scope")
		}
		assertBoundedGuarantees(t, block)
	}
}

func TestNodeAccountReceiveRPCSingleBlock(t *testing.T) {
	// Request identity and all commitments are selected from the original signed
	// fixture before observing any peer bytes or synthetic protocol-store result.
	user := accountBasicRPCUser(t)
	want := user.Vectors[1].Block
	if want.BlockType != chain.BlockTypeUserReceive || want.Height != 2 {
		t.Fatal("missing original receive selection")
	}
	state, bundle := accountReceiveRPCState(t)
	before := state.Snapshot()
	accepted, blocked := 0, 0
	for _, row := range loadAccountReceiveObservations(t) {
		t.Run(row.Name, func(t *testing.T) {
			client := accountBasicRPCPeer(t, user.RPCAddress, 2, []json.RawMessage{row.Wire})
			blocks, err := client.FetchAccountBlocksByHeight(context.Background(), user.RPCAddress, 2, 1)
			if expected := accountReceiveRPCError(t, row.Profile); expected != nil {
				if !errors.Is(err, expected) || blocks != nil {
					t.Fatal("changed signed receive input did not fail conversion without a partial result")
				}
				blocked++
			} else {
				if err != nil || len(blocks) != 1 || !reflect.DeepEqual(blocks[0], want) || blocks[0].ComputeHash() != row.ComputedHash {
					t.Fatal("production RPC conversion differs from the independently selected original receive")
				}
				assertReceiveRPCInclusion(t, state.VerifySegment(proof.AccountSegment{Address: user.Address, Blocks: blocks}, bundle.Commitments), 1)
				accepted++
			}
			if !reflect.DeepEqual(before, state.Snapshot()) {
				t.Fatal("receive RPC or inclusion query changed selected verified state")
			}
		})
	}
	if accepted != 36 || blocked != 8 {
		t.Fatalf("receive RPC inventory differs: accepted=%d blocked=%d", accepted, blocked)
	}
}

func TestNodeAccountReceiveRPCCompleteRange(t *testing.T) {
	user := accountBasicRPCUser(t)
	state, bundle := accountReceiveRPCState(t)
	before := state.Snapshot()
	want := []chain.AccountBlock{user.Vectors[0].Block, user.Vectors[1].Block}
	accepted, blocked := 0, 0
	for _, row := range loadAccountReceiveObservations(t) {
		t.Run(row.Name, func(t *testing.T) {
			// A valid first send cannot escape from a range whose later receive
			// fails conversion. Every selected profile exercises the complete range.
			client := accountBasicRPCPeer(t, user.RPCAddress, 1, []json.RawMessage{user.Vectors[0].RPC, row.Wire})
			blocks, err := client.FetchAccountBlocksByHeight(context.Background(), user.RPCAddress, 1, 2)
			if expected := accountReceiveRPCError(t, row.Profile); expected != nil {
				if !errors.Is(err, expected) || blocks != nil {
					t.Fatal("the valid first send leaked from a failed complete receive range")
				}
				blocked++
			} else {
				if err != nil || !reflect.DeepEqual(blocks, want) || blocks[1].ComputeHash() != row.ComputedHash {
					t.Fatal("original signed send/receive range changed in production RPC conversion")
				}
				assertReceiveRPCInclusion(t, state.VerifySegment(proof.AccountSegment{Address: user.Address, Blocks: blocks}, bundle.Commitments), 2)
				accepted++
			}
			if !reflect.DeepEqual(before, state.Snapshot()) {
				t.Fatal("complete receive range changed selected verified state")
			}
		})
	}
	if accepted != 36 || blocked != 8 {
		t.Fatalf("complete receive range inventory differs: accepted=%d blocked=%d", accepted, blocked)
	}
}

func TestNodeAccountReceiveRPCMatchCannotSupplyCommitmentInputs(t *testing.T) {
	user := accountBasicRPCUser(t)
	anchor, bundle := nodeAccountBundle(t)
	initial, err := verify.NewVerifiedState(anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	result, retained := initial.Extend(bundle.Headers)
	if result.Outcome != verify.OutcomeAccept {
		t.Fatal(result)
	}
	selected := 0
	for _, row := range loadAccountReceiveObservations(t) {
		if row.Profile != "exact" {
			continue
		}
		selected++
		t.Run(row.Name, func(t *testing.T) {
			if row.NodeResult != "MATCH" {
				t.Fatal("selected positive receive method observation missing")
			}
			client := accountBasicRPCPeer(t, user.RPCAddress, 2, []json.RawMessage{row.Wire})
			blocks, err := client.FetchAccountBlocksByHeight(context.Background(), user.RPCAddress, 2, 1)
			if err != nil || len(blocks) != 1 || !reflect.DeepEqual(blocks[0], user.Vectors[1].Block) {
				t.Fatal("selected positive receive conversion failed")
			}
			for _, tc := range []struct {
				name        string
				state       verify.VerifiedState
				commitments []proof.CommitmentEvidence
				reason      verify.ReasonCode
			}{{"header-not-retained", initial, bundle.Commitments, verify.ReasonHeightOutOfWindow},
				{"proof-not-supplied", retained, nil, verify.ReasonMissingProof}} {
				t.Run(tc.name, func(t *testing.T) {
					before := tc.state.Snapshot()
					result := tc.state.VerifySegment(proof.AccountSegment{Address: user.Address, Blocks: blocks}, tc.commitments)
					if len(result.Blocks) != 1 || result.Worst() != verify.OutcomeRefused || result.Blocks[0].Reason != tc.reason ||
						len(result.Blocks[0].Proven) != 0 || !reflect.DeepEqual(before, tc.state.Snapshot()) {
						t.Fatal("RPC conversion or node MATCH supplied absent commitment inputs")
					}
				})
			}
		})
	}
	if selected != 2 {
		t.Fatal("both positive receive methods must retain their commitment input boundaries")
	}
}
