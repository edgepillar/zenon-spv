package proof

import (
	"bytes"
	"encoding/json"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Budgets belong to one decode, never to a caller's reusable policy. Every
// decoded row consumes a slot, including rows replaced by repeated nested
// fields. This bounds decoding work as well as the final retained slices.
type rowBudget struct {
	field     string
	limit     int
	remaining int
}

func newRowBudget(field string, limit int) *rowBudget {
	if limit == 0 {
		return nil
	}
	return &rowBudget{field: field, limit: limit, remaining: limit}
}

type evidenceDecoder struct {
	limits DecodeLimits
	flat   *rowBudget
	blocks *rowBudget
}

func newEvidenceDecoder(limits DecodeLimits) evidenceDecoder {
	return evidenceDecoder{limits: limits,
		flat:   newRowBudget("total_flat_evidence_members", limits.MaxTotalFlatEvidenceMembers),
		blocks: newRowBudget("total_segment_blocks", limits.MaxTotalSegmentBlocks),
	}
}

func (e *evidenceDecoder) segment(d *json.Decoder, segment *AccountSegment) error {
	type plain AccountSegment
	wire := struct {
		*plain
		Blocks bundleRows[chain.AccountBlock] `json:"blocks"`
	}{plain: (*plain)(segment), Blocks: bundleRows[chain.AccountBlock]{
		target: &segment.Blocks, field: "segments.blocks", limit: e.limits.MaxSegmentBlocks, budget: e.blocks,
	}}
	return d.Decode(&wire)
}

func (e *evidenceDecoder) commitment(d *json.Decoder, commitment *CommitmentEvidence) error {
	type plain CommitmentEvidence
	wire := struct {
		*plain
		Flat flatEvidenceJSON `json:"flat"`
	}{plain: (*plain)(commitment), Flat: flatEvidenceJSON{target: &commitment.Flat, decoder: e}}
	return d.Decode(&wire)
}

func (e *evidenceDecoder) stateProof(d *json.Decoder, proof *StateValueProof) error {
	type plain StateValueProof
	wire := struct {
		*plain
		Nodes bundleRows[[]byte] `json:"proof_nodes"`
	}{plain: (*plain)(proof), Nodes: bundleRows[[]byte]{
		target: &proof.ProofNodes, field: "state_value_proofs.proof_nodes", limit: e.limits.MaxStateProofNodes,
	}}
	return d.Decode(&wire)
}

type flatEvidenceJSON struct {
	target  **FlatContentEvidence
	decoder *evidenceDecoder
}

func (flat *flatEvidenceJSON) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		*flat.target = nil
		return nil
	}
	var decoded FlatContentEvidence
	if *flat.target != nil {
		// Repeated objects retain omitted fields under encoding/json's legacy
		// merge rules. Repeated arrays still consume the shared row budget.
		decoded = **flat.target
	}
	wire := struct {
		Headers bundleRows[chain.AccountHeader] `json:"sorted_headers"`
	}{Headers: bundleRows[chain.AccountHeader]{target: &decoded.SortedHeaders,
		field: "commitments.flat.sorted_headers", limit: flat.decoder.limits.MaxFlatEvidenceMembers, budget: flat.decoder.flat,
	}}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	*flat.target = &decoded
	return nil
}
