package conformance_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func contractBatchBundle(t *testing.T) (accountSegmentCorpus, proof.HeaderBundle) {
	t.Helper()
	c := loadNodeAccountCorpus(t, "contract-batches.json")
	if len(c.Segments) != 1 || len(c.Segments[0].Vectors) != 5 || len(c.Batches) != 2 {
		t.Fatal("incomplete contract batch corpus")
	}
	bundle := accountBundleFromCorpus(t, c)
	if len(bundle.Commitments) != 5 {
		t.Fatal("every child and receive must appear directly in momentum content")
	}
	blocks := bundle.Segments[0].Blocks
	for i, kind := range []uint64{4, 4, 5, 4, 5} {
		if blocks[i].BlockType != kind || blocks[i].Height != uint64(i+1) {
			t.Fatal("wrong flattened contract batch order")
		}
	}
	var before chain.HashHeight
	for i, heights := range [][]uint64{{1, 2, 3}, {4, 5}} {
		batch := c.Batches[i]
		receive := blocks[heights[len(heights)-1]-1]
		if !slices.Equal(batch.CommitHeights, heights) || batch.ReceiveHeight != receive.Height || batch.Previous != before || receive.PreviousHash != blocks[receive.Height-2].BlockHash || receive.PreviousHash == before.Hash {
			t.Fatal("node transaction frontier was confused with raw previousHash")
		}
		var rpc struct {
			Descendants []struct{ Hash chain.Hash } `json:"descendantBlocks"`
		}
		if err := json.Unmarshal(c.Segments[0].Vectors[receive.Height-1].RPC, &rpc); err != nil {
			t.Fatal(err)
		}
		if len(rpc.Descendants) != len(heights)-1 {
			t.Fatal("wrong descendant count")
		}
		for j, child := range rpc.Descendants {
			if child.Hash != blocks[heights[j]-1].BlockHash {
				t.Fatal("receive descendants do not match the preceding child blocks")
			}
		}
		before = chain.HashHeight{Hash: receive.BlockHash, Height: receive.Height}
	}
	return c, bundle
}

func TestNodeContractBatchesDirectInclusion(t *testing.T) {
	c, bundle := contractBatchBundle(t)
	opts := verify.VerifyOptions{Policy: verify.DefaultPolicy()}
	initial, err := verify.NewVerifiedState(c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	r, state := initial.Extend(bundle.Headers)
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	resumed, err := verify.LoadTrustedState(path, c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	segment := bundle.Segments[0]
	for _, handle := range []verify.VerifiedState{state, resumed} {
		// Full batches and isolated children/receives use their own flat proof.
		// A direct child proof needs no sibling account bodies or receive body.
		for _, span := range [][2]int{{0, 5}, {0, 1}, {1, 2}, {2, 3}, {3, 5}, {4, 5}} {
			part := proof.AccountSegment{Address: segment.Address, Blocks: segment.Blocks[span[0]:span[1]]}
			evidence := bundle.Commitments[span[0]:span[1]]
			result := handle.VerifySegment(part, evidence)
			if len(result.Blocks) != len(part.Blocks) {
				t.Fatal("wrong segment result count")
			}
			for _, r := range result.Blocks {
				if r.Outcome != verify.OutcomeAccept || !slices.Contains(r.Proven, verify.GuaranteeContentInclusion) || slices.Contains(r.Proven, verify.GuaranteeSignatureAuthenticity) {
					t.Fatalf("incorrect embedded account guarantee: %v", r)
				}
				assertBoundedGuarantees(t, r)
			}
		}
		// Even the complete flat list attached to a receive is not implicitly
		// treated as a requested child's evidence. Its target must match.
		receives := []proof.CommitmentEvidence{bundle.Commitments[2], bundle.Commitments[4]}
		for _, span := range [][2]int{{0, 5}, {1, 2}, {3, 4}} {
			part := proof.AccountSegment{Address: segment.Address, Blocks: segment.Blocks[span[0]:span[1]]}
			result := handle.VerifySegment(part, receives)
			for i, r := range result.Blocks {
				want := verify.ReasonMissingProof
				if i > 0 {
					want = verify.ReasonParentNotAccepted
				}
				if r.Outcome != verify.OutcomeRefused || r.Reason != want || len(r.Proven) != 0 {
					t.Fatalf("receive evidence substituted for child evidence: %v", result.Blocks)
				}
			}
		}
		bad := bundle.Commitments[0]
		bad.Flat = &proof.FlatContentEvidence{SortedHeaders: slices.Clone(bad.Flat.SortedHeaders[1:])}
		result := handle.VerifySegment(segment, append([]proof.CommitmentEvidence{bad}, bundle.Commitments[1:]...))
		for i, r := range result.Blocks {
			want := verify.ReasonInvalidContent
			if i > 0 {
				want = verify.ReasonParentNotAccepted
			}
			if r.Outcome != verify.OutcomeReject || r.Reason != want || len(r.Proven) != 0 {
				t.Fatalf("incomplete flat content advanced a batch: %v", result.Blocks)
			}
		}
	}
}

func TestNodeContractBatchRPCDescendantTampering(t *testing.T) {
	for _, mutation := range []string{"reorder", "drop", "replace"} {
		t.Run(mutation, func(t *testing.T) {
			c := loadNodeAccountCorpus(t, "contract-batches.json")
			segment := c.Segments[0]
			var rpc map[string]json.RawMessage
			if err := json.Unmarshal(segment.Vectors[2].RPC, &rpc); err != nil {
				t.Fatal(err)
			}
			var children []json.RawMessage
			if err := json.Unmarshal(rpc["descendantBlocks"], &children); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "reorder":
				children[0], children[1] = children[1], children[0]
			case "drop":
				children = children[1:]
			case "replace":
				children[0] = segment.Vectors[3].RPC
			}
			var err error
			if rpc["descendantBlocks"], err = json.Marshal(children); err != nil {
				t.Fatal(err)
			}
			if segment.Vectors[2].RPC, err = json.Marshal(rpc); err != nil {
				t.Fatal(err)
			}
			blocks, err := tryFetchAccountSegmentVectors(t, segment)
			if !errors.Is(err, fetch.ErrHashMismatch) || blocks != nil {
				t.Fatalf("tampered receive returned a partial account batch: %v", err)
			}
		})
	}
}
