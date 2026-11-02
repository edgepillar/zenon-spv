// SPDX-License-Identifier: MIT

package proof

import "github.com/0x3639/zenon-spv/internal/chain"

// CandidateStateWitness is untrusted RPC data. Root is only a consistency hint;
// the verifier must obtain its authoritative root from owned header state.
// Value repeats bytes already carried by an inclusion proof and must agree.
// A missing RPC result is not a witness and is never represented by this zero
// value as application absence.
type CandidateStateWitness struct {
	Root  chain.Hash
	Value []byte
	Proof []byte
}

// CandidateSettlementBatch is the untrusted selected-node frontier DTO.
// Domain/Batch identify the key rather than additional stored ABI fields.
// IsFinalized is a frontier-derived hint, not membership or a predicate at H.
type CandidateSettlementBatch struct {
	DomainID    uint32
	BatchID     uint64
	Entry       CandidateBatchEntry
	IsFinalized bool
}
