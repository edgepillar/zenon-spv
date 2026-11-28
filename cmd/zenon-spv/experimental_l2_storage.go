// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

const experimentalL2StorageKeyBytes = 32

var (
	errExperimentalL2StorageProfile = errors.New("unsupported L2 storage profile")
	errExperimentalVaultValue       = errors.New("invalid vault balance value")
)

type experimentalL2StorageRequest struct {
	ContractID chain.Hash
	LocalKey   []byte
	Vault      *proof.CandidatePhase1VaultSelection
}

type experimentalL2StorageReport struct {
	DomainID      uint32                          `json:"domain_id"`
	BatchID       uint64                          `json:"batch_id"`
	PostStateRoot chain.Hash                      `json:"post_state_root"`
	ContractID    chain.Hash                      `json:"contract_id"`
	LocalKeyHex   string                          `json:"local_key_hex"`
	Path          chain.Hash                      `json:"path"`
	Present       bool                            `json:"present"`
	ValueHex      *string                         `json:"value_hex"`
	ProofBytes    int                             `json:"proof_bytes"`
	ProofSHA3     chain.Hash                      `json:"proof_sha3_256"`
	VaultBalance  *experimentalVaultBalanceReport `json:"vault_balance,omitempty"`
}

type experimentalVaultBalanceReport struct {
	AccountHex       string `json:"account_hex"`
	TokenStandardHex string `json:"token_standard_hex"`
	InterfaceSHA256  string `json:"interface_sha256"`
	AmountBaseUnits  string `json:"amount_base_units"`
}

func decodeExperimentalL2StorageRequest(raw []byte) (experimentalL2StorageRequest, error) {
	var contract, key string
	if decodeExperimentalCLIObject(raw, map[string]any{"contract_id": &contract, "local_key_hex": &key}) == nil {
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

	var vault json.RawMessage
	var account, token string
	if decodeExperimentalCLIObject(raw, map[string]any{"contract_id": &contract, "vault_balance": &vault}) != nil ||
		decodeExperimentalCLIObject(vault, map[string]any{"account_hex": &account, "token_standard_hex": &token}) != nil {
		return experimentalL2StorageRequest{}, errExperimentalCLIInput
	}
	selection, err := proof.ParseCandidatePhase1VaultSelection(contract, account, token)
	if err != nil {
		return experimentalL2StorageRequest{}, errExperimentalCLIInput
	}
	localKey := selection.LocalKey()
	return experimentalL2StorageRequest{ContractID: selection.ContractID, LocalKey: localKey[:], Vault: &selection}, nil
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
	selection := fetch.CandidateZenoStorageSelection{DomainID: batch.Context.Entry.DomainID, BatchID: batch.Request.BatchID,
		Path: proof.CandidatePhase1StoragePath(request.ContractID, request.LocalKey)}
	root := batch.Entry.PostStateRoot
	witness, err := fetch.DecodeCandidateZenoStorageWitness(raw, selection, &root)
	if err != nil {
		return experimentalL2StorageReport{}, err
	}

	limits := proof.CandidateSMTLimits{MaxProofBytes: proof.CandidateSMTMaxProofBytes, MaxValueBytes: proof.CandidateSMTMaxValueBytes}
	match, err := proof.ReadCandidateSMTProof(root, selection.Path, witness.Proof, limits)
	if err != nil || !match.Canonical || match.Present != witness.Present || !bytes.Equal(match.Value, witness.Value) {
		return experimentalL2StorageReport{}, fetch.ErrCandidateZenoStorageInvalid
	}
	report := experimentalL2StorageReport{
		DomainID: selection.DomainID, BatchID: selection.BatchID, PostStateRoot: root,
		ContractID: request.ContractID, LocalKeyHex: hex.EncodeToString(request.LocalKey), Path: selection.Path, Present: match.Present,
		ProofBytes: len(witness.Proof), ProofSHA3: chain.Hash(sha3.Sum256(witness.Proof)),
	}
	if match.Present {
		value := hex.EncodeToString(match.Value)
		report.ValueHex = &value
	}
	if request.Vault != nil {
		amount := "0" // The pinned balances map defines a proven absent leaf as zero.
		if match.Present {
			if len(match.Value) != 32 {
				return experimentalL2StorageReport{}, errExperimentalVaultValue
			}
			amount = new(big.Int).SetBytes(match.Value).String()
		}
		report.VaultBalance = &experimentalVaultBalanceReport{
			AccountHex: hex.EncodeToString(request.Vault.Account[:]), TokenStandardHex: hex.EncodeToString(request.Vault.TokenStandard[:]),
			InterfaceSHA256: proof.CandidatePhase1VaultInterfaceSHA256, AmountBaseUnits: amount,
		}
	}
	return report, nil
}
