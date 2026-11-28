// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

const (
	experimentalL2StorageKeyBytes = 32
	maxExperimentalL2WitnessBytes = 64 << 10
)

var (
	errExperimentalL2WitnessUnavailable = errors.New("L2 storage witness unavailable")
	errExperimentalL2WitnessIdentity    = errors.New("L2 storage witness identity mismatch")
	errExperimentalL2WitnessInvalid     = errors.New("invalid L2 storage witness")
	errExperimentalL2StorageProfile     = errors.New("unsupported L2 storage profile")
)

type experimentalL2StorageRequest struct {
	ContractID chain.Hash
	LocalKey   []byte
}

type experimentalL2StorageReport struct {
	DomainID      uint32     `json:"domain_id"`
	BatchID       uint64     `json:"batch_id"`
	PostStateRoot chain.Hash `json:"post_state_root"`
	ContractID    chain.Hash `json:"contract_id"`
	LocalKeyHex   string     `json:"local_key_hex"`
	Path          chain.Hash `json:"path"`
	Present       bool       `json:"present"`
	ValueHex      *string    `json:"value_hex"`
	ProofBytes    int        `json:"proof_bytes"`
	ProofSHA3     chain.Hash `json:"proof_sha3_256"`
}

func decodeExperimentalL2StorageRequest(raw []byte) (experimentalL2StorageRequest, error) {
	var contract, key string
	if decodeExperimentalCLIObject(raw, map[string]any{"contract_id": &contract, "local_key_hex": &key}) != nil {
		return experimentalL2StorageRequest{}, errExperimentalCLIInput
	}
	contractBytes, err := decodeExperimentalL2Hex(contract, chain.HashSize)
	if err != nil || len(contractBytes) != chain.HashSize {
		return experimentalL2StorageRequest{}, errExperimentalCLIInput
	}
	localKey, err := decodeExperimentalL2Hex(key, experimentalL2StorageKeyBytes)
	if err != nil {
		return experimentalL2StorageRequest{}, errExperimentalCLIInput
	}
	return experimentalL2StorageRequest{ContractID: chain.Hash(contractBytes), LocalKey: localKey}, nil
}

func decodeExperimentalL2Hex(value string, limit int) ([]byte, error) {
	if len(value) > 2*limit || strings.ContainsAny(value, "ABCDEF") {
		return nil, errExperimentalCLIInput
	}
	return hex.DecodeString(value)
}

// The caller passes the in-process successful three-row result. The provider
// cannot select the domain, batch, root or path, and its verified bit is a hint.
func checkExperimentalL2Storage(batch verify.ExperimentalBatchContextResult, request experimentalL2StorageRequest, raw []byte) (experimentalL2StorageReport, error) {
	if batch.Entry.ProtocolVersion != 1 || batch.DomainRecord.RuntimeKind != 0 || batch.DomainRecord.ExecProfile != 0 {
		return experimentalL2StorageReport{}, errExperimentalL2StorageProfile
	}
	if len(raw) > maxExperimentalL2WitnessBytes {
		return experimentalL2StorageReport{}, errExperimentalL2WitnessInvalid
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return experimentalL2StorageReport{}, errExperimentalL2WitnessUnavailable
	}

	var domain uint32
	var batchID uint64
	var root string
	var gatewayVerified bool
	var rows []json.RawMessage
	if decodeExperimentalCLIObject(raw, map[string]any{
		"domainId": &domain, "batchId": &batchID, "postStateRoot": &root,
		"verified": &gatewayVerified, "proofs": &rows,
	}) != nil || len(rows) != 1 {
		return experimentalL2StorageReport{}, errExperimentalL2WitnessInvalid
	}
	acceptedRoot := batch.Entry.PostStateRoot
	if domain != batch.Context.Entry.DomainID || batchID != batch.Request.BatchID || root != hex.EncodeToString(acceptedRoot[:]) {
		return experimentalL2StorageReport{}, errExperimentalL2WitnessIdentity
	}

	var preimage [chain.HashSize + experimentalL2StorageKeyBytes]byte
	copy(preimage[:chain.HashSize], request.ContractID[:])
	copy(preimage[chain.HashSize:], request.LocalKey)
	path := chain.Hash(sha3.Sum256(preimage[:chain.HashSize+len(request.LocalKey)]))

	var claimedPath, encodedProof string
	var present bool
	var value *string
	if decodeExperimentalCLIObject(rows[0], map[string]any{
		"path": &claimedPath, "present": &present, "value": &value, "proof": &encodedProof,
	}, "value") != nil || present != (value != nil) {
		return experimentalL2StorageReport{}, errExperimentalL2WitnessInvalid
	}
	if claimedPath != hex.EncodeToString(path[:]) {
		return experimentalL2StorageReport{}, errExperimentalL2WitnessIdentity
	}

	proofBytes, err := decodeExperimentalL2Hex(encodedProof, proof.CandidateSMTMaxProofBytes)
	if err != nil {
		return experimentalL2StorageReport{}, errExperimentalL2WitnessInvalid
	}
	limits := proof.CandidateSMTLimits{MaxProofBytes: proof.CandidateSMTMaxProofBytes, MaxValueBytes: proof.CandidateSMTMaxValueBytes}
	match, err := proof.ReadCandidateSMTProof(acceptedRoot, path, proofBytes, limits)
	if err != nil || !match.Canonical || match.Present != present ||
		present && *value != hex.EncodeToString(match.Value) {
		return experimentalL2StorageReport{}, errExperimentalL2WitnessInvalid
	}
	return experimentalL2StorageReport{
		DomainID: batch.Context.Entry.DomainID, BatchID: batch.Request.BatchID, PostStateRoot: acceptedRoot,
		ContractID: request.ContractID, LocalKeyHex: hex.EncodeToString(request.LocalKey), Path: path,
		Present: present, ValueHex: value, ProofBytes: len(proofBytes), ProofSHA3: chain.Hash(sha3.Sum256(proofBytes)),
	}, nil
}
