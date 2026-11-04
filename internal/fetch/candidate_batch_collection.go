// SPDX-License-Identifier: MIT

package fetch

import (
	"bytes"
	"context"
	"encoding/json"
	"unicode/utf8"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

// MaxCandidateBatchBundleBytes caps the complete experimental provider document.
// It is an unsupported-work boundary, not a node or consensus parameter.
const MaxCandidateBatchBundleBytes = 8 * 1024 * 1024

// CandidateBatchCollectionSelection is caller-selected request identity, not
// trusted header state. Collection never derives these selectors from a peer's
// frontier, proof, gateway or environment. The owned verifier still requires its
// own independently selected genesis/anchor/profile/schedule and context pins.
type CandidateBatchCollectionSelection struct {
	ChainID      uint64
	AnchorHeight uint64
	AnchorHash   chain.Hash
	Height       uint64
	HeaderHash   chain.Hash
	TipHeight    uint64
	TipHash      chain.Hash
	Settlement   chain.Address
	DomainID     uint32
	BatchID      uint64
}

// Validate rejects inconsistent local identity before any RPC request. The
// explicit heights imply a complete range immediately after the given anchor;
// the existing candidate-v3 range/header/byte limits remain in force.
func (s CandidateBatchCollectionSelection) Validate() error {
	if s.ChainID == 0 || s.AnchorHeight == 0 || s.TipHeight <= s.AnchorHeight ||
		s.TipHeight-s.AnchorHeight > MaxCandidateV3RangeHeaders || s.Height <= s.AnchorHeight || s.Height > s.TipHeight ||
		s.AnchorHash.IsZero() || s.HeaderHash.IsZero() || s.TipHash.IsZero() || s.Settlement == (chain.Address{}) ||
		s.Height == s.TipHeight && s.HeaderHash != s.TipHash {
		return ErrInvalidQuery
	}
	return nil
}

type collectedCandidateMomentum struct {
	header chain.CandidateV3Header
	wire   json.RawMessage
}

type collectedCandidateMomentumDecoder struct{ target *collectedCandidateMomentum }

func (d *collectedCandidateMomentumDecoder) UnmarshalJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return ErrCandidateV3Momentum
	}
	value, err := DecodeCandidateV3Momentum(raw)
	if err != nil {
		return err
	}
	// The projection contains a data hash, not the original data bytes. Preserve
	// the validated wire row independently; it cannot be rebuilt from that hash.
	*d.target = collectedCandidateMomentum{header: value.Header, wire: bytes.Clone(raw)}
	return nil
}

// FetchCandidateBatchEntryBundle performs only bounded, read-only candidate
// acquisition. Returned bytes have the existing experimental CLI provider
// schema. Success authenticates no signature, producer, network, root, proof,
// typed value or gateway finality. The offline owned verifier remains necessary.
// All selected reads must complete before any document is returned. Errors
// return nil, including missing results, later-page failure and cancellation.
func (c *Client) FetchCandidateBatchEntryBundle(ctx context.Context, selected CandidateBatchCollectionSelection, compareGateway bool) ([]byte, error) {
	return c.fetchCandidateBatchBundle(ctx, selected, compareGateway, false)
}

// FetchCandidateBatchContextBundle collects three exact, locally derived keys
// at the same selected height. The command-specific witnesses object cannot
// supply profiles, contexts or keys to the offline verifier. Each RPC response
// is capped separately at 32 KiB, so the three proof responses together are
// bounded by 96 KiB, in addition to the existing header and final bundle caps.
// Missing/failed later reads return nil rather than a partial provider bundle.
func (c *Client) FetchCandidateBatchContextBundle(ctx context.Context, selected CandidateBatchCollectionSelection, compareGateway bool) ([]byte, error) {
	if selected.DomainID == 0 {
		return nil, ErrInvalidQuery
	}
	return c.fetchCandidateBatchBundle(ctx, selected, compareGateway, true)
}

type collectedBatchContextWitnesses struct {
	BatchEntry   json.RawMessage `json:"batch_entry"`
	DomainRecord json.RawMessage `json:"domain_record"`
	DomainConfig json.RawMessage `json:"domain_config"`
}

func (c *Client) fetchCandidateBatchBundle(ctx context.Context, selected CandidateBatchCollectionSelection, compareGateway, withContext bool) ([]byte, error) {
	if err := selected.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c == nil || c.HTTP == nil {
		return nil, ErrInvalidQuery
	}
	start, count := selected.AnchorHeight+1, selected.TipHeight-selected.AnchorHeight
	previous := selected.AnchorHash
	rows, err := fetchHeightRange(ctx, c, "ledger.getMomentumsByHeight", start, count,
		func(height, size uint64) []any { return []any{height, size} },
		func(target *collectedCandidateMomentum) any { return &collectedCandidateMomentumDecoder{target} },
		func(row collectedCandidateMomentum, index uint64) (json.RawMessage, error) {
			h := row.header.Header
			if h.Height != start+index || h.ChainIdentifier != selected.ChainID || h.PreviousHash != previous ||
				h.Height == selected.Height && h.HeaderHash != selected.HeaderHash ||
				index == count-1 && h.HeaderHash != selected.TipHash {
				return nil, ErrQueryMismatch
			}
			previous = h.HeaderHash
			return row.wire, nil
		}, &rpcResponseBudget{remaining: MaxCandidateV3RangeBytes})
	if err != nil {
		return nil, err
	}
	key := proof.CandidateSettlementBatchEntryKey(selected.Settlement, selected.DomainID, selected.BatchID)
	witness, err := c.collectCandidateResult(ctx, "ledger.getProof", []any{selected.Height, key[:]}, func(raw []byte) error {
		_, err := DecodeCandidateStateWitness(raw)
		return err
	})
	if err != nil {
		return nil, err
	}
	var witnesses *collectedBatchContextWitnesses
	if withContext {
		recordKey := proof.CandidateSettlementDomainRecordKey(selected.Settlement, selected.DomainID)
		configKey := proof.CandidateSettlementDomainConfigKey(selected.Settlement, selected.DomainID)
		witnesses = &collectedBatchContextWitnesses{BatchEntry: witness}
		for _, next := range [...]struct {
			key    [27]byte
			target *json.RawMessage
		}{{recordKey, &witnesses.DomainRecord}, {configKey, &witnesses.DomainConfig}} {
			*next.target, err = c.collectCandidateResult(ctx, "ledger.getProof", []any{selected.Height, next.key[:]}, func(raw []byte) error {
				_, err := DecodeCandidateStateWitness(raw)
				return err
			})
			if err != nil {
				return nil, err
			}
		}
		witness = nil // The three-row schema has no legacy witness field.
	}
	var gateway json.RawMessage
	if compareGateway {
		gateway, err = c.collectCandidateResult(ctx, "embedded.settlement.getBatch", []any{selected.DomainID, selected.BatchID}, func(raw []byte) error {
			value, err := DecodeCandidateSettlementBatch(raw)
			if err != nil {
				return err
			}
			if value.DomainID != selected.DomainID || value.BatchID != selected.BatchID {
				return ErrQueryMismatch
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(struct {
		Version   uint32                          `json:"version"`
		Momentums []json.RawMessage               `json:"momentums"`
		Witness   json.RawMessage                 `json:"witness,omitempty"`
		Witnesses *collectedBatchContextWitnesses `json:"witnesses,omitempty"`
		Gateway   json.RawMessage                 `json:"gateway,omitempty"`
	}{1, rows, witness, witnesses, gateway}); err != nil {
		return nil, ErrInvalidRPCResponse
	}
	if output.Len() > MaxCandidateBatchBundleBytes {
		return nil, ErrResponseTooLarge
	}
	return output.Bytes(), nil
}

func (c *Client) collectCandidateResult(ctx context.Context, method string, params []any, validate func([]byte) error) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := c.callWithBudget(ctx, method, params, &raw, &rpcResponseBudget{remaining: MaxCandidateStateResponseBytes}); err != nil {
		return nil, err
	}
	if err := validate(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
