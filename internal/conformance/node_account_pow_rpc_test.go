package conformance_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestNodeAccountPoWRPCOriginal(t *testing.T) {
	user := accountBasicRPCUser(t)
	original := user.Vectors[0].Block
	state, bundle := accountReceiveRPCState(t)
	before := state.Snapshot()
	accepted, blocked := 0, 0
	for _, row := range loadAccountPoWObservations(t) {
		t.Run(row.Name, func(t *testing.T) {
			accountPoWBlock(t, row, original)
			client := accountBasicRPCPeer(t, user.RPCAddress, 1, []json.RawMessage{row.Wire})
			blocks, err := client.FetchAccountBlocksByHeight(context.Background(), user.RPCAddress, 1, 1)
			if row.Profile == originalAccountPoWProfile {
				if err != nil || len(blocks) != 1 || !reflect.DeepEqual(blocks[0], original) {
					t.Fatal("original signed account changed during RPC conversion")
				}
				assertReceiveRPCInclusion(t, state.VerifySegment(proof.AccountSegment{Address: user.Address, Blocks: blocks}, bundle.Commitments), 1)
				accepted++
			} else {
				if !errors.Is(err, fetch.ErrHashMismatch) || blocks != nil {
					t.Fatal("changed PoW inputs bypassed hash conversion or returned a partial result")
				}
				blocked++
			}
			if !reflect.DeepEqual(before, state.Snapshot()) {
				t.Fatal("account PoW RPC query changed selected verified state")
			}
		})
	}
	if accepted != 2 || blocked != 62 {
		t.Fatal("original account PoW RPC inventory differs")
	}
	logAccountPoWBoundary(t, "rpc-original", 64, accepted, blocked, 0)
}

func TestNodeAccountPoWRPCCoherentHash(t *testing.T) {
	user := accountBasicRPCUser(t)
	state, bundle := accountReceiveRPCState(t)
	before := state.Snapshot()
	checked := 0
	for _, row := range loadAccountPoWObservations(t) {
		if row.Profile == originalAccountPoWProfile {
			continue
		}
		t.Run(row.Name, func(t *testing.T) {
			want := accountPoWBlock(t, row, user.Vectors[0].Block)
			want.BlockHash = want.ComputeHash()
			// RawMessage keeps uint64 values above 2^53 exact. Only the claimed
			// hash changes; the original nonce, difficulty and signature remain.
			var wire map[string]json.RawMessage
			if err := json.Unmarshal(row.Wire, &wire); err != nil {
				t.Fatal(err)
			}
			var err error
			if wire["hash"], err = json.Marshal(want.BlockHash); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			client := accountBasicRPCPeer(t, user.RPCAddress, 1, []json.RawMessage{raw})
			blocks, err := client.FetchAccountBlocksByHeight(context.Background(), user.RPCAddress, 1, 1)
			if err != nil || len(blocks) != 1 || !reflect.DeepEqual(blocks[0], want) {
				t.Fatal("coherent-hash transport lost the exact selected PoW or signature bytes")
			}
			result := state.VerifySegment(proof.AccountSegment{Address: user.Address, Blocks: blocks}, bundle.Commitments)
			if len(result.Blocks) != 1 || result.Worst() != verify.OutcomeReject ||
				result.Blocks[0].Reason != verify.ReasonInvalidSignature || len(result.Blocks[0].Proven) != 0 ||
				!reflect.DeepEqual(before, state.Snapshot()) {
				t.Fatal("hash-checked RPC transport or matching work supplied a signature")
			}
			checked++
		})
	}
	if checked != 62 {
		t.Fatal("coherent-hash account PoW RPC inventory differs")
	}
	logAccountPoWBoundary(t, "rpc-coherent-hash", checked, 0, checked, 0)
}

func TestNodeAccountPoWRPCCompleteRange(t *testing.T) {
	user := accountBasicRPCUser(t)
	state, bundle := accountReceiveRPCState(t)
	before := state.Snapshot()
	want := []chain.AccountBlock{user.Vectors[0].Block, user.Vectors[1].Block}
	accepted, blocked := 0, 0
	for _, row := range loadAccountPoWObservations(t) {
		t.Run(row.Name, func(t *testing.T) {
			accountPoWBlock(t, row, want[0])
			// A valid following receive must not escape a range whose earlier
			// send failed hash conversion. No retry or filtered range is used.
			client := accountBasicRPCPeer(t, user.RPCAddress, 1, []json.RawMessage{row.Wire, user.Vectors[1].RPC})
			blocks, err := client.FetchAccountBlocksByHeight(context.Background(), user.RPCAddress, 1, 2)
			if row.Profile == originalAccountPoWProfile {
				if err != nil || !reflect.DeepEqual(blocks, want) {
					t.Fatal("original signed send/receive range changed during RPC conversion")
				}
				assertReceiveRPCInclusion(t, state.VerifySegment(proof.AccountSegment{Address: user.Address, Blocks: blocks}, bundle.Commitments), 2)
				accepted++
			} else {
				if !errors.Is(err, fetch.ErrHashMismatch) || blocks != nil {
					t.Fatal("a later original receive escaped from a failed complete PoW range")
				}
				blocked++
			}
			if !reflect.DeepEqual(before, state.Snapshot()) {
				t.Fatal("complete PoW range changed selected verified state")
			}
		})
	}
	if accepted != 2 || blocked != 62 {
		t.Fatal("complete account PoW RPC range inventory differs")
	}
	logAccountPoWBoundary(t, "rpc-complete-range", 64, accepted, blocked, 0)
}

func TestNodeAccountPoWMatchCannotSupplyCommitmentInputs(t *testing.T) {
	user := accountBasicRPCUser(t)
	anchor, bundle := nodeAccountBundle(t)
	initial, err := verify.NewVerifiedState(anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	r, retained := initial.Extend(bundle.Headers)
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	checked := 0
	for _, row := range loadAccountPoWObservations(t) {
		if row.Profile != originalAccountPoWProfile {
			continue
		}
		if row.NodeResult != "MATCH" {
			t.Fatal("selected original positive node observation missing")
		}
		for _, layer := range []string{"runtime", "rpc"} {
			for _, tc := range []struct {
				name        string
				state       verify.VerifiedState
				commitments []proof.CommitmentEvidence
				reason      verify.ReasonCode
			}{{"header-not-retained", initial, bundle.Commitments, verify.ReasonHeightOutOfWindow},
				{"proof-not-supplied", retained, nil, verify.ReasonMissingProof}} {
				t.Run(row.Name+"/"+layer+"/"+tc.name, func(t *testing.T) {
					blocks := []chain.AccountBlock{accountPoWBlock(t, row, user.Vectors[0].Block)}
					if layer == "rpc" {
						client := accountBasicRPCPeer(t, user.RPCAddress, 1, []json.RawMessage{row.Wire})
						blocks, err = client.FetchAccountBlocksByHeight(context.Background(), user.RPCAddress, 1, 1)
						if err != nil || len(blocks) != 1 || !reflect.DeepEqual(blocks[0], user.Vectors[0].Block) {
							t.Fatal("original positive PoW method conversion failed")
						}
					}
					before := tc.state.Snapshot()
					result := tc.state.VerifySegment(proof.AccountSegment{Address: user.Address, Blocks: blocks}, tc.commitments)
					if len(result.Blocks) != 1 || result.Worst() != verify.OutcomeRefused ||
						result.Blocks[0].Reason != tc.reason || len(result.Blocks[0].Proven) != 0 ||
						!reflect.DeepEqual(before, tc.state.Snapshot()) {
						t.Fatal("node work/method or transport supplied absent commitment inputs")
					}
					checked++
				})
			}
		}
	}
	if checked != 8 {
		t.Fatal("both methods/layers must retain both absent commitment boundaries")
	}
	logAccountPoWBoundary(t, "missing-commitment-inputs", checked, 0, 0, checked)
}
