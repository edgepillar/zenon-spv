// SPDX-License-Identifier: MIT

package fetch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

// MaxCandidateStateResponseBytes bounds complete RPC bytes, including wrappers
// and whitespace. It is a local transport budget, not a protocol value cap.
const MaxCandidateStateResponseBytes int64 = 32 * 1024

var (
	ErrCandidateStateWitness     = errors.New("invalid candidate state witness")
	ErrCandidateStateUnavailable = errors.New("candidate state result is unavailable")
)

// DecodeCandidateStateWitness decodes the selected node's result object only.
// It checks exact field/encoding/byte limits, not the proof or root authority.
// A null value is permitted for an absence witness; a null result/proof is not
// application absence. A failure returns no partial candidate.
func DecodeCandidateStateWitness(raw []byte) (proof.CandidateStateWitness, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return proof.CandidateStateWitness{}, ErrCandidateStateUnavailable
	}
	if int64(len(raw)) > MaxCandidateStateResponseBytes || !utf8.Valid(raw) {
		return proof.CandidateStateWitness{}, ErrCandidateStateWitness
	}
	var next proof.CandidateStateWitness
	var value, witness json.RawMessage
	if decodeCandidateRPCObjectNullable(raw, map[string]any{"root": &next.Root, "value": &value, "proof": &witness}, "value") != nil {
		return proof.CandidateStateWitness{}, ErrCandidateStateWitness
	}
	var err error
	if next.Proof, err = decodeCandidateRPCBytes(witness, 99, proof.CandidateSMTMaxProofBytes); err != nil {
		return proof.CandidateStateWitness{}, ErrCandidateStateWitness
	}
	if !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		if next.Value, err = decodeCandidateRPCBytes(value, 0, proof.CandidateSMTMaxValueBytes); err != nil {
			return proof.CandidateStateWitness{}, ErrCandidateStateWitness
		}
	}
	return next, nil
}

// FetchCandidateBatchEntryProof derives the full key from caller-selected
// inputs before making the height-bound ledger.getProof read. The returned
// root/value are untrusted consistency hints. An owned verifier must choose
// the root from its accepted H/hash/context and exact retained tip.
func (c *Client) FetchCandidateBatchEntryProof(ctx context.Context, height uint64, settlement chain.Address, domain uint32, batch uint64) (proof.CandidateStateWitness, error) {
	if err := validateHeightRange(height, 1); err != nil {
		return proof.CandidateStateWitness{}, err
	}
	key := proof.CandidateSettlementBatchEntryKey(settlement, domain, batch)
	var next proof.CandidateStateWitness
	decoder := candidateStateWitnessDecoder{target: &next}
	if err := c.callWithBudget(ctx, "ledger.getProof", []any{height, key[:]}, &decoder, &rpcResponseBudget{remaining: MaxCandidateStateResponseBytes}); err != nil {
		return proof.CandidateStateWitness{}, err
	}
	return next, nil
}

type candidateStateWitnessDecoder struct{ target *proof.CandidateStateWitness }

func (d *candidateStateWitnessDecoder) UnmarshalJSON(raw []byte) error {
	next, err := DecodeCandidateStateWitness(raw)
	if err != nil {
		return err
	}
	*d.target = next
	return nil
}
