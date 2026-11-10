package proof

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"

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
		target: &segment.Blocks, field: "segments.blocks", limit: e.limits.MaxSegmentBlocks, budget: e.blocks, decode: e.accountBlock,
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
	var decodeNode func(*json.Decoder, *[]byte) error
	if limit := e.limits.MaxStateProofBytes; limit > 0 {
		// One budget per proof, shared by repeated proof_nodes fields. A later
		// array or null cannot refund bytes already decoded from this object.
		budget := &proofByteBudget{limit: limit, remaining: limit}
		decodeNode = budget.decodeNode
	}
	type plain StateValueProof
	wire := struct {
		*plain
		Nodes bundleRows[[]byte] `json:"proof_nodes"`
	}{plain: (*plain)(proof), Nodes: bundleRows[[]byte]{
		target: &proof.ProofNodes, field: "state_value_proofs.proof_nodes", limit: e.limits.MaxStateProofNodes, decode: decodeNode,
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
		capacityHint: flatRowsCapacityHint, decodeValidated: decodeFlatAccountHeaderRows,
	}}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	*flat.target = &decoded
	return nil
}

const compactFlatAddressPrefix = `{"address":"`

// encoding/json checks the complete value before invoking this private
// callback. The direct path accepts the standard compact row layout and the
// first other layout hands the remaining rows to the ordinary decoder.
func decodeFlatAccountHeaderRows(rows *bundleRows[chain.AccountHeader], raw []byte) error {
	if !bytes.HasPrefix(raw, []byte("["+compactFlatAddressPrefix)) {
		return rows.decodeJSONRows(json.NewDecoder(bytes.NewReader(raw)), raw, nil)
	}
	cursor := bundleValueCursor{raw: raw, at: 1}
	decoded := make([]chain.AccountHeader, 0, rows.initialCapacity(raw[1:]))
	for {
		if err := rows.checkRowLimit(len(decoded)); err != nil {
			return err
		}
		row, consumed := parseCompactFlatAccountHeader(raw[cursor.at:])
		if consumed == 0 {
			// The current row and the closing bracket already belong to a
			// validated array. Retain the decoded prefix and its budget charges.
			suffix := io.MultiReader(bytes.NewReader([]byte{'['}), bytes.NewReader(raw[cursor.at:]))
			return rows.decodeJSONRows(json.NewDecoder(suffix), nil, decoded)
		}
		decoded = append(decoded, row)
		if rows.budget != nil {
			rows.budget.remaining--
		}
		cursor.at += consumed
		cursor.space()
		if raw[cursor.at] == ']' {
			*rows.target = decoded
			return nil
		}
		cursor.at++ // Comma, checked by the enclosing JSON decode.
		cursor.space()
	}
}

// Return the length of one compact object at the start of the remaining
// input. A zero length selects the ordinary decoder for this row.
func parseCompactFlatAccountHeader(raw []byte) (chain.AccountHeader, int) {
	const (
		heightPrefix = `","height":`
		hashPrefix   = `,"hash":"`
		suffix       = `"}`
		addressStart = len(compactFlatAddressPrefix)
		addressEnd   = addressStart + 2*chain.AddressSize
		heightStart  = addressEnd + len(heightPrefix)
		hashTail     = len(hashPrefix) + 2*chain.HashSize + len(suffix)
	)
	var row chain.AccountHeader
	if len(raw) < heightStart+1+hashTail ||
		!bytes.HasPrefix(raw, []byte(compactFlatAddressPrefix)) ||
		!bytes.Equal(raw[addressEnd:heightStart], []byte(heightPrefix)) {
		return row, 0
	}
	heightWidth := bytes.IndexByte(raw[heightStart:heightStart+21], ',')
	if heightWidth <= 0 || heightWidth > 1 && raw[heightStart] == '0' {
		return row, 0
	}
	heightEnd := heightStart + heightWidth
	end := heightEnd + hashTail
	if len(raw) < end || !bytes.HasPrefix(raw[heightEnd:end], []byte(hashPrefix)) ||
		!bytes.HasSuffix(raw[heightEnd:end], []byte(suffix)) {
		return row, 0
	}
	n, err := strconv.ParseUint(string(raw[heightStart:heightEnd]), 10, 64)
	if err != nil {
		return row, 0
	}
	if row.Address.UnmarshalText(raw[addressStart:addressEnd]) != nil ||
		row.Hash.UnmarshalText(raw[heightEnd+len(hashPrefix):end-len(suffix)]) != nil {
		return chain.AccountHeader{}, 0
	}
	row.Height = n
	return row, end
}
