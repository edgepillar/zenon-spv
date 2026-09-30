package verify

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func TestRetainedSummaryInitialization(t *testing.T) {
	if _, err := (VerifiedState{}).RetainedSummary(); !errors.Is(err, ErrUninitializedState) {
		t.Fatal("zero handle exposed a retained summary")
	}
	state, err := NewVerifiedState(GenesisTrustRoot{ChainID: 3, Height: 100, HeaderHash: chain.Hash{1}}, VerifyOptions{Policy: Policy{W: 6}})
	if err != nil {
		t.Fatal(err)
	}
	summary, err := state.RetainedSummary()
	if err != nil || !reflect.DeepEqual(summary, RetainedSummary{Capacity: 7}) {
		t.Fatalf("empty state claimed bounds or depth: %+v %v", summary, err)
	}
}

func TestRetainedSummaryMatchesProofDepthAtHeightBoundaries(t *testing.T) {
	for _, anchorHeight := range []uint64{100, ^uint64(0) - 3} {
		for _, depth := range []uint64{0, 1, 2, 60} {
			anchor := GenesisTrustRoot{ChainID: 99, Height: anchorHeight, HeaderHash: chain.Hash{1}}
			member := chain.AccountHeader{Address: chain.Address{1}, Height: 1, Hash: chain.Hash{2}}
			flat := []chain.AccountHeader{member}
			previous := anchor
			headers := make([]chain.Header, 3)
			for i := range headers {
				headers[i] = boundaryHeader(previous, anchorHeight+uint64(i)+1, chain.MomentumContentHash(flat))
				previous.Height, previous.HeaderHash = headers[i].Height, headers[i].HeaderHash
			}
			state, err := NewVerifiedState(anchor, VerifyOptions{Policy: Policy{W: min(depth, 2)}})
			if err != nil {
				t.Fatal(err)
			}
			r, state := state.Extend(headers)
			if r.Outcome != OutcomeAccept {
				t.Fatal(r)
			}
			if depth > 2 {
				// A larger resume policy cannot manufacture missing depth.
				path := filepath.Join(t.TempDir(), "state.json")
				if err := state.Save(path); err != nil {
					t.Fatal(err)
				}
				state, err = LoadTrustedState(path, anchor, VerifyOptions{Policy: Policy{W: depth}})
				if err != nil {
					t.Fatal(err)
				}
			}
			summary, err := state.RetainedSummary()
			if err != nil || summary.Capacity != int(depth)+1 || summary.Count != min(3, int(depth)+1) || summary.Tip.Height != anchorHeight+3 || summary.Tip.Hash != headers[2].HeaderHash {
				t.Fatalf("retained bounds differ from verified headers: %+v %v", summary, err)
			}
			first := headers[3-summary.Count]
			if summary.Oldest.Height != first.Height || summary.Oldest.Hash != first.HeaderHash {
				t.Fatal("oldest retained header ignored eviction")
			}
			for _, header := range headers {
				eligible := summary.DepthEligible != nil && header.Height >= summary.DepthEligible.FromHeight && header.Height <= summary.DepthEligible.ThroughHeight
				r := state.VerifyCommitment(proof.CommitmentEvidence{Height: header.Height, Target: member,
					Flat: &proof.FlatContentEvidence{SortedHeaders: flat}})
				if eligible != (r.Outcome == OutcomeAccept) {
					t.Fatalf("diagnostic depth disagrees with proof query: anchor=%d depth=%d height=%d result=%s", anchorHeight, depth, header.Height, r)
				}
			}
		}
	}
}

func TestRetainedSummaryValuesAreDetached(t *testing.T) {
	state, _, evidence, _ := verifiedStateFixture(t)
	before := state.Snapshot()
	summary, err := state.RetainedSummary()
	if err != nil || summary.DepthEligible == nil {
		t.Fatal("fixture lacks a depth-eligible target")
	}
	summary.Oldest.Hash[0] ^= 1
	summary.Tip.Height = 0
	summary.DepthEligible.ThroughHeight = ^uint64(0)
	if !reflect.DeepEqual(before, state.Snapshot()) || state.VerifyCommitment(evidence).Outcome != OutcomeAccept {
		t.Fatal("diagnostic mutation changed evidence")
	}
	again, err := state.RetainedSummary()
	if err != nil || again.DepthEligible.FromHeight != 101 || again.DepthEligible.ThroughHeight != 101 || again.Tip.Height != 103 {
		t.Fatal("diagnostic pointers alias the owned state")
	}
}
