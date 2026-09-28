package verify

import (
	"crypto/ed25519"
	"reflect"
	"sort"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func boundaryHeader(anchor GenesisTrustRoot, height uint64, content chain.Hash) chain.Header {
	key := ed25519.NewKeyFromSeed(fixtureSeed)
	h := chain.Header{Version: 1, ChainIdentifier: anchor.ChainID, PreviousHash: anchor.HeaderHash,
		Height: height, TimestampUnix: 1700000000, ContentHash: content, PublicKey: key.Public().(ed25519.PublicKey)}
	h.HeaderHash = h.ComputeHash()
	h.Signature = ed25519.Sign(key, h.HeaderHash[:])
	return h
}

func TestVerifyHeaders_HeightCannotWrapToZero(t *testing.T) {
	anchor := GenesisTrustRoot{ChainID: 99, Height: ^uint64(0), HeaderHash: chain.Hash{1}}
	policy := Policy{W: 1}
	state := NewHeaderState(anchor, policy)
	h := boundaryHeader(anchor, 0, chain.Hash{2})
	r, after := VerifyHeaders([]chain.Header{h}, state, policy)
	if r.Outcome != OutcomeReject || r.Reason != ReasonHeightNonMonotonic || len(r.Proven) != 0 || !reflect.DeepEqual(after, state) {
		t.Fatalf("wrapped height was accepted or advanced state: %s", r)
	}
}

func TestVerifyCommitment_DepthCannotOverflow(t *testing.T) {
	const max = ^uint64(0)
	anchor := GenesisTrustRoot{ChainID: 99, Height: max - 3, HeaderHash: chain.Hash{1}}
	member := chain.AccountHeader{Address: chain.Address{1}, Height: 1, Hash: chain.Hash{2}}
	flat := []chain.AccountHeader{member}
	content := chain.MomentumContentHash(flat)
	previous := anchor
	headers := make([]chain.Header, 3)
	for i := range headers {
		headers[i] = boundaryHeader(previous, max-2+uint64(i), content)
		previous.Height, previous.HeaderHash = headers[i].Height, headers[i].HeaderHash
	}
	policy := Policy{W: 2}
	r, state := VerifyHeaders(headers, NewHeaderState(anchor, policy), policy)
	if r.Outcome != OutcomeAccept {
		t.Fatalf("valid extension through maximum height failed: %s", r)
	}
	for _, tc := range []struct {
		height, depth uint64
		accept        bool
	}{
		{max - 2, 2, true},
		{max - 2, 3, false},
		{max - 2, max, false},
		{max, 0, true},
		{max, 1, false},
	} {
		evidence := proof.CommitmentEvidence{Height: tc.height, Target: member,
			Flat: &proof.FlatContentEvidence{SortedHeaders: flat}}
		result := VerifyCommitment(state, evidence, Policy{W: tc.depth})
		if tc.accept {
			if result.Outcome != OutcomeAccept {
				t.Fatalf("height=%d depth=%d: %s", tc.height, tc.depth, result)
			}
		} else if result.Outcome != OutcomeRefused || result.Reason != ReasonInsufficientFinality || len(result.Proven) != 0 {
			t.Fatalf("overflow granted unearned depth: height=%d depth=%d: %s", tc.height, tc.depth, result)
		}
	}
}

func TestVerifySegment_HeightCannotWrapToZero(t *testing.T) {
	const max = ^uint64(0)
	for _, tc := range []struct {
		name    string
		heights []uint64
		reasons []ReasonCode
	}{
		{"maximum-successor", []uint64{max - 1, max}, []ReasonCode{ReasonOK, ReasonOK}},
		{"wrapped-successor", []uint64{max, 0, 1}, []ReasonCode{ReasonOK, ReasonHeightNonMonotonic, ReasonParentNotAccepted}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, segment, _, key := segmentFixture(t)
			template := segment.Blocks[0]
			segment.Blocks = make([]chain.AccountBlock, len(tc.heights))
			flat := make([]chain.AccountHeader, len(tc.heights))
			for i, height := range tc.heights {
				b := template
				b.Height = height
				if i > 0 {
					b.PreviousHash = segment.Blocks[i-1].BlockHash
				}
				b.BlockHash = b.ComputeHash()
				b.Signature = ed25519.Sign(key, b.BlockHash[:])
				segment.Blocks[i], flat[i] = b, b.AccountHeader()
			}
			sort.Slice(flat, func(i, j int) bool { return flat[i].Height < flat[j].Height })
			anchor := GenesisTrustRoot{ChainID: template.ChainIdentifier, Height: 100, HeaderHash: chain.Hash{1}}
			h := boundaryHeader(anchor, 101, chain.MomentumContentHash(flat))
			policy := Policy{W: 0}
			r, state := VerifyHeaders([]chain.Header{h}, NewHeaderState(anchor, policy), policy)
			if r.Outcome != OutcomeAccept {
				t.Fatalf("fixture momentum failed verification: %s", r)
			}
			commitments := make([]proof.CommitmentEvidence, len(flat))
			for i, target := range flat {
				commitments[i] = proof.CommitmentEvidence{Height: h.Height, Target: target,
					Flat: &proof.FlatContentEvidence{SortedHeaders: flat}}
			}
			result := VerifySegment(state, segment, commitments, policy)
			for i, want := range tc.reasons {
				got := result.Blocks[i]
				if want == ReasonOK {
					if got.Outcome != OutcomeAccept {
						t.Fatalf("block[%d] should accept: %s", i, got)
					}
				} else if got.Outcome != OutcomeReject || got.Reason != want || len(got.Proven) != 0 {
					t.Errorf("block[%d] should reject with %s and no guarantees: %s", i, want, got)
				}
			}
		})
	}
}
