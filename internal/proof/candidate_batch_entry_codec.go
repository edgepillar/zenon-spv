// SPDX-License-Identifier: MIT

package proof

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf8"

	"github.com/0x3639/zenon-spv/internal/chain"
)

const (
	CandidateBatchEntryHeadBytes = 17 * 32
	CandidateBatchEntryMinBytes  = CandidateBatchEntryHeadBytes + 3*32
)

var (
	ErrCandidateBatchEntryBounds   = errors.New("candidate BatchEntry exceeds explicit research limits")
	ErrCandidateBatchEntryEncoding = errors.New("malformed candidate BatchEntry encoding")
)

// CandidateBatchEntryStringRule makes string interpretation an explicit local
// choice. Neither choice establishes the selected network's accepted policy.
type CandidateBatchEntryStringRule uint8

const (
	CandidateBatchEntryOpaqueString CandidateBatchEntryStringRule = 1
	CandidateBatchEntryUTF8String   CandidateBatchEntryStringRule = 2
)

// CandidateBatchEntryLimits bounds the complete value, each dynamic field and
// their cumulative unpadded payload. All byte limits must be positive and no
// greater than MaxValueBytes; zero never disables a cap. MaxValueBytes must be
// between CandidateBatchEntryMinBytes and CandidateSMTMaxValueBytes. These are
// research-work ceilings, not an agreed network profile or proof-data budget.
type CandidateBatchEntryLimits struct {
	MaxValueBytes            int
	MaxExecutorPillarBytes   int
	MaxAssetFlowSummaryBytes int
	MaxProofDataBytes        int
	MaxDynamicBytes          int
	StringRule               CandidateBatchEntryStringRule
}

// CandidateBatchEntry is detached, untrusted ABI data from the selected node's
// 17-field Settlement schema at revision 938fca3b7787da86827a5eb63371509b36e14761.
// It carries no network, key, header, root, context, acceptance or finality
// authority. ProtocolVersion, DaMode and State remain uninterpreted numbers;
// sequence, height, pillar-name and business rules need separate validation.
type CandidateBatchEntry struct {
	ProtocolVersion   uint16
	FirstInputSeq     uint64
	LastInputSeq      uint64
	PreStateRoot      chain.Hash
	PostStateRoot     chain.Hash
	InputRoot         chain.Hash
	ReceiptRoot       chain.Hash
	EventRoot         chain.Hash
	OutboxRoot        chain.Hash
	DaHash            chain.Hash
	DaMode            uint8
	ExecutorPillar    string
	SubmittedAtHeight uint64
	FinalizeAtHeight  uint64
	AssetFlowSummary  []byte
	ProofData         []byte
	State             uint8
}

// DecodeCandidateBatchEntry enforces a strict local canonical encoding: full
// unsigned widths, contiguous schema-ordered dynamic tails, exact offsets,
// zero padding and no trailing data. This is deliberately stricter than the
// selected node's permissive unpacker. It does not assert network agreement.
//
// Dynamic output copies follow all bounds and structural checks. An error
// returns no partial value. The caller must not mutate raw concurrently.
// Decoding does not check a proof or enable VerifyStateValue or v3 acceptance.
func DecodeCandidateBatchEntry(raw []byte, limits CandidateBatchEntryLimits) (CandidateBatchEntry, error) {
	if limits.MaxValueBytes < CandidateBatchEntryMinBytes || limits.MaxValueBytes > CandidateSMTMaxValueBytes ||
		(limits.StringRule != CandidateBatchEntryOpaqueString && limits.StringRule != CandidateBatchEntryUTF8String) {
		return CandidateBatchEntry{}, ErrCandidateBatchEntryBounds
	}
	for _, cap := range [...]int{limits.MaxExecutorPillarBytes, limits.MaxAssetFlowSummaryBytes, limits.MaxProofDataBytes, limits.MaxDynamicBytes} {
		if cap <= 0 || cap > limits.MaxValueBytes {
			return CandidateBatchEntry{}, ErrCandidateBatchEntryBounds
		}
	}
	if len(raw) > limits.MaxValueBytes {
		return CandidateBatchEntry{}, ErrCandidateBatchEntryBounds
	}
	if len(raw) < CandidateBatchEntryMinBytes {
		return CandidateBatchEntry{}, ErrCandidateBatchEntryEncoding
	}
	word := func(index int) []byte { return raw[index*32 : (index+1)*32] }
	var value CandidateBatchEntry
	integers := [...]struct {
		index int
		width int
	}{
		{0, 2}, {1, 8}, {2, 8}, {10, 1}, {12, 8}, {13, 8}, {16, 1},
	}
	var decoded [7]uint64
	for i, field := range integers {
		n, ok := candidateBatchEntryUint(word(field.index), field.width)
		if !ok {
			return CandidateBatchEntry{}, ErrCandidateBatchEntryEncoding
		}
		decoded[i] = n
	}
	value.ProtocolVersion, value.FirstInputSeq, value.LastInputSeq = uint16(decoded[0]), decoded[1], decoded[2]
	value.DaMode, value.SubmittedAtHeight, value.FinalizeAtHeight, value.State = uint8(decoded[3]), decoded[4], decoded[5], uint8(decoded[6])
	for i, hash := range [...]*chain.Hash{&value.PreStateRoot, &value.PostStateRoot, &value.InputRoot, &value.ReceiptRoot, &value.EventRoot, &value.OutboxRoot, &value.DaHash} {
		copy(hash[:], word(i+3))
	}
	var fields [3][]byte
	tails := [...]struct {
		index int
		cap   int
	}{
		{11, limits.MaxExecutorPillarBytes}, {14, limits.MaxAssetFlowSummaryBytes}, {15, limits.MaxProofDataBytes},
	}
	cursor, cumulative := CandidateBatchEntryHeadBytes, 0
	for i, field := range tails {
		offset, ok := candidateBatchEntryUint(word(field.index), 8)
		if !ok || offset != uint64(cursor) || len(raw)-cursor < 32 {
			return CandidateBatchEntry{}, ErrCandidateBatchEntryEncoding
		}
		n, ok := candidateBatchEntryUint(raw[cursor:cursor+32], 8)
		if !ok {
			return CandidateBatchEntry{}, ErrCandidateBatchEntryEncoding
		}
		if n > uint64(field.cap) || n > uint64(limits.MaxDynamicBytes-cumulative) {
			return CandidateBatchEntry{}, ErrCandidateBatchEntryBounds
		}
		start := cursor + 32
		if n > uint64(len(raw)-start) {
			return CandidateBatchEntry{}, ErrCandidateBatchEntryEncoding
		}
		// n is bounded by both the input and a <= 4096-byte cap before int conversion.
		end := start + int(n)
		cursor = end + (-int(n) & 31)
		if cursor > len(raw) || !candidateBatchEntryZero(raw[end:cursor]) {
			return CandidateBatchEntry{}, ErrCandidateBatchEntryEncoding
		}
		fields[i] = raw[start:end]
		cumulative += int(n)
	}
	if cursor != len(raw) || (limits.StringRule == CandidateBatchEntryUTF8String && !utf8.Valid(fields[0])) {
		return CandidateBatchEntry{}, ErrCandidateBatchEntryEncoding
	}
	value.ExecutorPillar = string(fields[0])
	value.AssetFlowSummary, value.ProofData = bytes.Clone(fields[1]), bytes.Clone(fields[2])
	return value, nil
}

func candidateBatchEntryUint(word []byte, width int) (uint64, bool) {
	if !candidateBatchEntryZero(word[:32-width]) {
		return 0, false
	}
	return binary.BigEndian.Uint64(word[24:]), true
}

func candidateBatchEntryZero(raw []byte) bool {
	for _, b := range raw {
		if b != 0 {
			return false
		}
	}
	return true
}
