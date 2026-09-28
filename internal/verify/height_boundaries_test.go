package verify

import (
	"crypto/ed25519"
	"reflect"
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
