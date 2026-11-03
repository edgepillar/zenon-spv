// SPDX-License-Identifier: MIT

package proof

import (
	"bytes"
	"errors"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// CandidateSMTMaxSetProofs is a local three-witness research ceiling. A larger
// collection needs a separately reviewed work policy, not an unbounded slice.
const CandidateSMTMaxSetProofs = 3

var ErrCandidateSMTDuplicatePath = errors.New("candidate SMT proof set repeats a selected path")

// CandidateSMTProofInput selects one path and explicit individual limits. Path
// is already the SHA3-256 application-key position. MaxSiblings is inclusive;
// zero allows no encoded siblings and never disables that cap.
type CandidateSMTProofInput struct {
	Path        chain.Hash
	Proof       []byte
	Limits      CandidateSMTLimits
	MaxSiblings int
}

// CandidateSMTSetLimits bounds the complete collection, including repeated
// encoded sibling work. Count and byte caps must be positive. Zero siblings is
// an explicit no-sibling policy. Every cap is bounded by the local research
// ceiling, independent of architecture or input lengths.
type CandidateSMTSetLimits struct {
	MaxProofs          int
	MaxTotalProofBytes int
	MaxTotalValueBytes int
	MaxTotalSiblings   int
}

// ReadCandidateSMTProofSet reads one to three distinct paths against exactly one
// caller-selected root. It checks all framing and individual/aggregate work
// limits before hashing or copying values, then verifies every mathematical
// match before allocating detached results. Any error returns a nil slice.
//
// Presence and canonical encoding remain facts for an enclosing policy to
// require. This API neither derives application keys nor authenticates the
// root, header, height, domain, context, coverage or ABI semantics. It creates
// no owned state and does not enable runtime state-value acceptance. The caller
// must not mutate inputs concurrently.
func ReadCandidateSMTProofSet(root chain.Hash, inputs []CandidateSMTProofInput, limits CandidateSMTSetLimits) ([]CandidateSMTMatch, error) {
	if limits.MaxProofs <= 0 || limits.MaxProofs > CandidateSMTMaxSetProofs ||
		limits.MaxTotalProofBytes < 99 || limits.MaxTotalProofBytes > limits.MaxProofs*CandidateSMTMaxProofBytes ||
		limits.MaxTotalValueBytes <= 0 || limits.MaxTotalValueBytes > limits.MaxProofs*CandidateSMTMaxValueBytes ||
		limits.MaxTotalSiblings < 0 || limits.MaxTotalSiblings > limits.MaxProofs*256 ||
		len(inputs) == 0 || len(inputs) > limits.MaxProofs {
		return nil, ErrCandidateSMTBounds
	}
	remainingProofBytes := limits.MaxTotalProofBytes
	for i, input := range inputs {
		if !validCandidateSMTLimits(input.Limits) || input.MaxSiblings < 0 || input.MaxSiblings > 256 ||
			len(input.Proof) > input.Limits.MaxProofBytes || len(input.Proof) > remainingProofBytes {
			return nil, ErrCandidateSMTBounds
		}
		remainingProofBytes -= len(input.Proof)
		for j := 0; j < i; j++ {
			if input.Path == inputs[j].Path {
				return nil, ErrCandidateSMTDuplicatePath
			}
		}
	}
	var views [CandidateSMTMaxSetProofs]candidateSMTView
	remainingValues, remainingSiblings := limits.MaxTotalValueBytes, limits.MaxTotalSiblings
	for i, input := range inputs {
		view, err := parseCandidateSMT(input.Proof, input.Limits)
		if err != nil {
			return nil, err
		}
		if view.count > input.MaxSiblings || view.count > remainingSiblings || len(view.value) > remainingValues {
			return nil, ErrCandidateSMTBounds
		}
		remainingValues -= len(view.value)
		remainingSiblings -= view.count
		views[i] = view
	}
	var matches [CandidateSMTMaxSetProofs]CandidateSMTMatch
	for i, view := range views[:len(inputs)] {
		match, err := view.check(root, inputs[i].Path, nil, false, false)
		if err != nil {
			return nil, err
		}
		matches[i] = match
	}
	result := make([]CandidateSMTMatch, len(inputs))
	for i, match := range matches[:len(inputs)] {
		match.Value = bytes.Clone(match.Value)
		result[i] = match
	}
	return result, nil
}
