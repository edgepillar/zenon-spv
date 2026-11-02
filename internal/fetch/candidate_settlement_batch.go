// SPDX-License-Identifier: MIT

package fetch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/0x3639/zenon-spv/internal/proof"
)

var ErrCandidateSettlementBatch = errors.New("invalid candidate Settlement batch")

// DecodeCandidateSettlementBatch decodes the selected source's frontier DTO.
// It neither binds that frontier to H nor authenticates the stored fields.
// IsFinalized remains a frontier-derived hint, distinct from the 17 ABI fields.
func DecodeCandidateSettlementBatch(raw []byte) (proof.CandidateSettlementBatch, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return proof.CandidateSettlementBatch{}, ErrCandidateStateUnavailable
	}
	if int64(len(raw)) > MaxCandidateStateResponseBytes || !utf8.Valid(raw) {
		return proof.CandidateSettlementBatch{}, ErrCandidateSettlementBatch
	}
	var next proof.CandidateSettlementBatch
	v := &next.Entry
	var asset, data json.RawMessage
	if decodeCandidateRPCObjectNullable(raw, map[string]any{
		"domainId": &next.DomainID, "batchId": &next.BatchID,
		"protocolVersion": &v.ProtocolVersion, "firstInputSeq": &v.FirstInputSeq, "lastInputSeq": &v.LastInputSeq,
		"preStateRoot": &v.PreStateRoot, "postStateRoot": &v.PostStateRoot, "inputRoot": &v.InputRoot,
		"receiptRoot": &v.ReceiptRoot, "eventRoot": &v.EventRoot, "outboxRoot": &v.OutboxRoot, "daHash": &v.DaHash,
		"daMode": &v.DaMode, "executorPillar": &v.ExecutorPillar, "submittedAtHeight": &v.SubmittedAtHeight,
		"finalizeAtHeight": &v.FinalizeAtHeight, "assetFlowSummary": &asset, "proofData": &data,
		"state": &v.State, "isFinalized": &next.IsFinalized,
	}, "assetFlowSummary", "proofData") != nil || len(v.ExecutorPillar) > proof.CandidateSMTMaxValueBytes || !utf8.ValidString(v.ExecutorPillar) {
		return proof.CandidateSettlementBatch{}, ErrCandidateSettlementBatch
	}
	var err error
	// A Go []byte can be nil in the source DTO. Both null and empty base64
	// represent empty ABI byte fields; a null whole result remains unavailable.
	if !bytes.Equal(bytes.TrimSpace(asset), []byte("null")) {
		if v.AssetFlowSummary, err = decodeCandidateRPCBytes(asset, 0, proof.CandidateSMTMaxValueBytes); err != nil {
			return proof.CandidateSettlementBatch{}, ErrCandidateSettlementBatch
		}
	}
	if !bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		if v.ProofData, err = decodeCandidateRPCBytes(data, 0, proof.CandidateSMTMaxValueBytes); err != nil {
			return proof.CandidateSettlementBatch{}, ErrCandidateSettlementBatch
		}
	}
	return next, nil
}

// FetchCandidateSettlementBatch performs a read of frontier context, not a
// historical query. The selected IDs must match; no height/finality or proof
// authority is obtained from this DTO. A missing result remains unavailable.
func (c *Client) FetchCandidateSettlementBatch(ctx context.Context, domain uint32, batch uint64) (proof.CandidateSettlementBatch, error) {
	var next proof.CandidateSettlementBatch
	decoder := candidateSettlementBatchDecoder{target: &next}
	if err := c.callWithBudget(ctx, "embedded.settlement.getBatch", []any{domain, batch}, &decoder, &rpcResponseBudget{remaining: MaxCandidateStateResponseBytes}); err != nil {
		return proof.CandidateSettlementBatch{}, err
	}
	if next.DomainID != domain || next.BatchID != batch {
		return proof.CandidateSettlementBatch{}, ErrQueryMismatch
	}
	return next, nil
}

type candidateSettlementBatchDecoder struct {
	target *proof.CandidateSettlementBatch
}

func (d *candidateSettlementBatchDecoder) UnmarshalJSON(raw []byte) error {
	next, err := DecodeCandidateSettlementBatch(raw)
	if err != nil {
		return err
	}
	*d.target = next
	return nil
}
