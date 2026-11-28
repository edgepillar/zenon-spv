// SPDX-License-Identifier: MIT

package fetch

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

const MaxCandidateZenoStorageResultBytes = 64 << 10

var (
	ErrCandidateZenoStorageUnavailable = errors.New("unavailable Zeno storage witness")
	ErrCandidateZenoStorageIdentity    = errors.New("mismatched Zeno storage witness identity")
	ErrCandidateZenoStorageInvalid     = errors.New("invalid Zeno storage witness")
)

type CandidateZenoStorageSelection struct {
	DomainID uint32
	BatchID  uint64
	Path     chain.Hash
}

type CandidateZenoStorageWitness struct {
	Present bool
	Value   []byte
	Proof   []byte
}

// DecodeCandidateZenoStorageWitness checks the bounded, single-path gateway
// result. Only an independently verified caller can supply an accepted root.
func DecodeCandidateZenoStorageWitness(raw []byte, selection CandidateZenoStorageSelection, acceptedRoot *chain.Hash) (CandidateZenoStorageWitness, error) {
	if len(raw) > MaxCandidateZenoStorageResultBytes || !utf8.Valid(raw) {
		return CandidateZenoStorageWitness{}, ErrCandidateZenoStorageInvalid
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return CandidateZenoStorageWitness{}, ErrCandidateZenoStorageUnavailable
	}
	var domain uint32
	var batch uint64
	var root string
	var verified bool
	var rows []json.RawMessage
	if decodeCandidateRPCObjectNullable(raw, map[string]any{
		"domainId": &domain, "batchId": &batch, "postStateRoot": &root,
		"verified": &verified, "proofs": &rows,
	}) != nil || len(rows) != 1 {
		return CandidateZenoStorageWitness{}, ErrCandidateZenoStorageInvalid
	}
	rootBytes, err := decodeZenoStorageHex(root, chain.HashSize)
	if err != nil || len(rootBytes) != chain.HashSize {
		return CandidateZenoStorageWitness{}, ErrCandidateZenoStorageInvalid
	}
	if domain != selection.DomainID || batch != selection.BatchID ||
		acceptedRoot != nil && chain.Hash(rootBytes) != *acceptedRoot {
		return CandidateZenoStorageWitness{}, ErrCandidateZenoStorageIdentity
	}
	var path, encodedProof string
	var value *string
	var witness CandidateZenoStorageWitness
	if decodeCandidateRPCObjectNullable(rows[0], map[string]any{
		"path": &path, "present": &witness.Present, "value": &value, "proof": &encodedProof,
	}, "value") != nil || witness.Present != (value != nil) {
		return CandidateZenoStorageWitness{}, ErrCandidateZenoStorageInvalid
	}
	if path != hex.EncodeToString(selection.Path[:]) {
		return CandidateZenoStorageWitness{}, ErrCandidateZenoStorageIdentity
	}
	witness.Proof, err = decodeZenoStorageHex(encodedProof, proof.CandidateSMTMaxProofBytes)
	if err != nil || len(witness.Proof) < 99 {
		return CandidateZenoStorageWitness{}, ErrCandidateZenoStorageInvalid
	}
	if value != nil {
		witness.Value, err = decodeZenoStorageHex(*value, proof.CandidateSMTMaxValueBytes)
		if err != nil {
			return CandidateZenoStorageWitness{}, ErrCandidateZenoStorageInvalid
		}
	}
	return witness, nil
}

func decodeZenoStorageHex(text string, limit int) ([]byte, error) {
	if len(text) > 2*limit || strings.ContainsAny(text, "ABCDEF") {
		return nil, ErrCandidateZenoStorageInvalid
	}
	return hex.DecodeString(text)
}

// FetchCandidateZenoStorage issues one numeric-batch proof read. The raw
// result remains a candidate and carries no accepted root or storage claim.
func (c *Client) FetchCandidateZenoStorage(ctx context.Context, selection CandidateZenoStorageSelection) (json.RawMessage, error) {
	if selection.DomainID == 0 || selection.Path.IsZero() {
		return nil, ErrCandidateZenoStorageIdentity
	}
	const responseBytes = MaxCandidateZenoStorageResultBytes + 1024
	raw, err := c.callResultWithBudget(ctx, "zeno_getProof",
		[]any{selection.DomainID, []chain.Hash{selection.Path}, selection.BatchID},
		&rpcResponseBudget{remaining: responseBytes})
	if err != nil {
		var remote *rpcError
		if errors.As(err, &remote) && remote.Code >= -32004 && remote.Code <= -32002 {
			return nil, ErrCandidateZenoStorageUnavailable
		}
		return nil, err
	}
	if _, err := DecodeCandidateZenoStorageWitness(raw, selection, nil); err != nil {
		return nil, err
	}
	return raw, nil
}
