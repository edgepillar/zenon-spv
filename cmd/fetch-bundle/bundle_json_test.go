package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func TestBoundedBundleJSONMatchesWireFormat(t *testing.T) {
	flat := &proof.FlatContentEvidence{SortedHeaders: []chain.AccountHeader{{Height: 9}}}
	for _, bundle := range []proof.HeaderBundle{
		{Version: proof.WireVersion},
		{Version: proof.WireVersion, Headers: []chain.Header{}, Commitments: []proof.CommitmentEvidence{}, Segments: []proof.AccountSegment{}},
		{
			Version: proof.WireVersion, ChainID: 3, ClaimedGenesis: chain.Hash{1},
			Headers: []chain.Header{{Version: 1, Height: 2, PublicKey: []byte{1}, Signature: []byte{2}}, {Version: 2, Height: 3, NextFusionPrice: 1000, NextWorkPrice: 2000}},
			Commitments: []proof.CommitmentEvidence{
				{Height: 2, Flat: flat}, {Height: 3, Flat: flat}, {Height: 4}, {Flat: &proof.FlatContentEvidence{}},
			},
			Segments: []proof.AccountSegment{
				{Address: chain.Address{2}, Blocks: []chain.AccountBlock{{Height: 9, Amount: big.NewInt(123), PublicKey: []byte{3}}, {Height: 10}}},
				{Blocks: nil}, {Blocks: []chain.AccountBlock{}},
			},
			StateValueProofs: []proof.StateValueProof{{KeyKind: "<reserved>&\n\"", Key: []byte{0, 1}, ProofNodes: [][]byte{nil, {}, {1, 2}}}},
		},
	} {
		want, err := json.Marshal(bundle)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, '\n')
		for _, limit := range []int64{1, int64(len(want) - 1), int64(len(want)), int64(len(want) + 1)} {
			got, err := encodeBundleBounded(bundle, limit)
			if limit < int64(len(want)) {
				if !errors.Is(err, proof.ErrBundleTooLarge) || got != nil {
					t.Fatalf("oversized encoding returned partial output: len=%d err=%v", len(got), err)
				}
				continue
			}
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("bounded JSON differs from standard wire encoding: %v", err)
			}
			if _, err := proof.UnmarshalHeaderBundleJSON(got); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestBoundedBundleJSONRequiresPositiveLimit(t *testing.T) {
	for _, limit := range []int64{0, -1} {
		if got, err := encodeBundleBounded(proof.HeaderBundle{}, limit); err == nil || got != nil {
			t.Fatal("invalid byte limit accepted")
		}
	}
}

func TestBoundedJSONStopsVisitingItemsAfterLimit(t *testing.T) {
	w := boundedJSON{limit: 3}
	visited := 0
	w.array(10000, false, func(int) {
		visited++
		w.raw("12345")
	})
	if visited != 1 || w.buf.Len() > 3 || !errors.Is(w.err, proof.ErrBundleTooLarge) {
		t.Fatalf("encoder continued after byte refusal: visits=%d size=%d err=%v", visited, w.buf.Len(), w.err)
	}
}

func FuzzBoundedBundleJSON(f *testing.F) {
	f.Add([]byte{1, 2, 3}, uint16(256))
	f.Add([]byte{}, uint16(1))
	f.Fuzz(func(t *testing.T, input []byte, limit uint16) {
		if len(input) > 4096 {
			t.Skip()
		}
		b := proof.HeaderBundle{Version: proof.WireVersion, Headers: []chain.Header{{Version: 1, Signature: input}}}
		b.Segments = []proof.AccountSegment{{Blocks: []chain.AccountBlock{{PublicKey: input, Signature: input}}}}
		for _, v := range input {
			b.Commitments = append(b.Commitments, proof.CommitmentEvidence{Height: uint64(v), Flat: &proof.FlatContentEvidence{SortedHeaders: []chain.AccountHeader{{Height: uint64(v)}}}})
		}
		want, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, '\n')
		got, err := encodeBundleBounded(b, int64(limit)+1)
		if len(want) > int(limit)+1 {
			if !errors.Is(err, proof.ErrBundleTooLarge) || got != nil {
				t.Fatal("oversized encoding returned bytes")
			}
		} else if err != nil || !bytes.Equal(got, want) {
			t.Fatal("wire encoding mismatch")
		}
	})
}
