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

// commitments reads element spans from a syntax-checked bundle. Check the row
// limit before decoding the next value and publish the slice only on success.
func (e *evidenceDecoder) commitments(cursor *bundleValueCursor, target *[]CommitmentEvidence) error {
	rows := bundleRows[CommitmentEvidence]{target: target, field: "commitments", limit: e.limits.MaxCommitments}
	if cursor.raw[cursor.at] != '[' {
		// Preserve the ordinary token handling for null and non-array values.
		start := cursor.at
		cursor.value()
		return rows.UnmarshalJSON(cursor.raw[start:cursor.at])
	}
	cursor.at++
	cursor.space()
	decoded := make([]CommitmentEvidence, 0)
	var previous flatDecodeRecord
	for cursor.raw[cursor.at] != ']' {
		if err := rows.checkRowLimit(len(decoded)); err != nil {
			return err
		}
		// After a comma, include the spaces before the next row, as
		// json.Decoder.Decode does for its type-error offsets.
		start := cursor.at
		cursor.space()
		cursor.value()
		raw := cursor.raw[start:cursor.at]
		cursor.space()
		var stableInput []byte
		if cursor.raw[cursor.at] != ']' {
			stableInput = raw
		}
		decoded = append(decoded, CommitmentEvidence{})
		if err := e.decodeCommitment(func(target any) error { return json.Unmarshal(raw, target) },
			&decoded[len(decoded)-1], &previous, stableInput); err != nil {
			return err
		}
		if cursor.raw[cursor.at] == ']' {
			break
		}
		cursor.at++ // Comma, checked by complete-document validation.
	}
	cursor.at++ // Closing bracket.
	*target = decoded
	return nil
}

func (e *evidenceDecoder) decodeCommitment(decode func(any) error, commitment *CommitmentEvidence, previous *flatDecodeRecord, stableInput []byte) error {
	type plain CommitmentEvidence
	wire := struct {
		*plain
		Flat flatEvidenceJSON `json:"flat"`
	}{plain: (*plain)(commitment), Flat: flatEvidenceJSON{
		target: &commitment.Flat, decoder: e, fromDecoder: true, previous: previous, stableInput: stableInput,
	}}
	return decode(&wire)
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
	target      **FlatContentEvidence
	decoder     *evidenceDecoder
	fromDecoder bool // A complete value has passed encoding/json's syntax check.
	previous    *flatDecodeRecord
	stableInput []byte // Space-inclusive commitment span in the bounded document.
}

// flatDecodeRecord keeps a single successfully decoded canonical flat object
// for the lifetime of the commitment array. Its rows are private until the
// complete bundle is published and each result receives independent storage.
type flatDecodeRecord struct {
	wire    []byte
	headers []chain.AccountHeader
}

func (previous flatDecodeRecord) copyHeaders(raw []byte, limit int, budget *rowBudget) []chain.AccountHeader {
	count := len(previous.headers)
	if count == 0 || limit > 0 && count > limit ||
		budget != nil && count > budget.remaining || !bytes.Equal(raw, previous.wire) {
		return nil
	}
	headers := make([]chain.AccountHeader, count)
	copy(headers, previous.headers)
	if budget != nil {
		budget.remaining -= count
	}
	return headers
}

func (flat *flatEvidenceJSON) UnmarshalJSON(raw []byte) error {
	var decoded FlatContentEvidence
	if *flat.target != nil {
		// Repeated objects retain omitted fields under encoding/json's legacy
		// merge rules. Repeated arrays still consume the shared row budget.
		decoded = **flat.target
	}
	if flat.previous != nil {
		if headers := flat.previous.copyHeaders(raw, flat.decoder.limits.MaxFlatEvidenceMembers, flat.decoder.flat); headers != nil {
			decoded.SortedHeaders = headers
			*flat.target = &decoded
			return nil
		}
		*flat.previous = flatDecodeRecord{}
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		*flat.target = nil
		return nil
	}
	wire := struct {
		Headers bundleRows[chain.AccountHeader] `json:"sorted_headers"`
	}{Headers: bundleRows[chain.AccountHeader]{target: &decoded.SortedHeaders,
		field: "commitments.flat.sorted_headers", limit: flat.decoder.limits.MaxFlatEvidenceMembers, budget: flat.decoder.flat,
		capacityHint: flatRowsCapacityHint, decodeValidated: decodeFlatAccountHeaderRows,
	}}
	var array []byte
	if flat.fromDecoder {
		array = singleFlatHeaderArray(raw)
	}
	var err error
	if array != nil {
		err = wire.Headers.UnmarshalJSON(array)
		if typeErr, ok := err.(*json.UnmarshalTypeError); ok {
			// Preserve the field context the anonymous wire struct supplies.
			field := "sorted_headers"
			if typeErr.Field != "" {
				field += "." + typeErr.Field
			}
			typeErr.Struct = ""
			typeErr.Field = field
		}
	} else {
		err = json.Unmarshal(raw, &wire)
	}
	if err != nil {
		return err
	}
	if array != nil && flat.previous != nil && len(decoded.SortedHeaders) > 0 {
		// Locate these bytes in the stable bundle span. The JSON callback
		// may supply temporary storage for raw.
		if start := bytes.Index(flat.stableInput, raw); start >= 0 {
			*flat.previous = flatDecodeRecord{flat.stableInput[start : start+len(raw)], decoded.SortedHeaders}
		}
	}
	*flat.target = &decoded
	return nil
}

// singleFlatHeaderArray borrows the array in a syntax-checked object with
// exactly one canonical field. The ordinary decoder handles other layouts,
// including aliases and repeated fields that share the decode-wide budget.
func singleFlatHeaderArray(raw []byte) []byte {
	const prefix = `{"sorted_headers":`
	if !bytes.HasPrefix(raw, []byte(prefix+"[")) {
		return nil
	}
	cursor := bundleValueCursor{raw: raw, at: len(prefix)}
	cursor.value()
	end := cursor.at
	cursor.space()
	if cursor.at != len(raw)-1 || raw[cursor.at] != '}' {
		return nil
	}
	return raw[len(prefix):end]
}

const compactFlatAddressPrefix = `{"address":"`

type compactFlatAddress struct {
	text  []byte
	value chain.Address
}

// encoding/json checks the complete value before invoking this private
// callback. The direct path accepts the standard compact row layout and the
// first other layout hands the remaining rows to the ordinary decoder.
func decodeFlatAccountHeaderRows(rows *bundleRows[chain.AccountHeader], raw []byte) error {
	if !bytes.HasPrefix(raw, []byte("["+compactFlatAddressPrefix)) {
		return rows.decodeJSONRows(json.NewDecoder(bytes.NewReader(raw)), raw, nil)
	}
	cursor := bundleValueCursor{raw: raw, at: 1}
	decoded := make([]chain.AccountHeader, 0, rows.initialCapacity(raw[1:]))
	var lastAddress compactFlatAddress
	for {
		if err := rows.checkRowLimit(len(decoded)); err != nil {
			return err
		}
		row, consumed := parseCompactFlatAccountHeader(raw[cursor.at:], &lastAddress)
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
func parseCompactFlatAccountHeader(raw []byte, lastAddress *compactFlatAddress) (chain.AccountHeader, int) {
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
	addressText := raw[addressStart:addressEnd]
	if bytes.Equal(addressText, lastAddress.text) {
		row.Address = lastAddress.value
	} else {
		if row.Address.UnmarshalText(addressText) != nil {
			return chain.AccountHeader{}, 0
		}
		// This slice is local to the validated array decode. Returned
		// account headers own their fixed-size address bytes.
		*lastAddress = compactFlatAddress{text: addressText, value: row.Address}
	}
	if row.Hash.UnmarshalText(raw[heightEnd+len(hashPrefix):end-len(suffix)]) != nil {
		return chain.AccountHeader{}, 0
	}
	row.Height = n
	return row, end
}
