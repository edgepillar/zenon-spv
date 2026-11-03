// SPDX-License-Identifier: MIT

package proof

import (
	"bytes"
	"errors"

	"github.com/0x3639/zenon-spv/internal/chain"
)

const (
	CandidateDomainRecordHeadBytes = 12 * 32
	CandidateDomainRecordMinBytes  = CandidateDomainRecordHeadBytes + 2*32
	CandidateDomainConfigBytes     = 2 * 32
)

var (
	ErrCandidateDomainBounds   = errors.New("candidate domain context exceeds explicit research limits")
	ErrCandidateDomainEncoding = errors.New("malformed candidate domain context encoding")
)

// CandidateDomainRecordLimits bounds the complete value, each opaque dynamic
// field and their cumulative unpadded payload. Every cap must be positive; zero
// does not disable a cap or express a source-specific empty-field requirement.
// MaxValueBytes must be between CandidateDomainRecordMinBytes and the candidate
// SMT research ceiling. These limits do not select an accepted network policy.
type CandidateDomainRecordLimits struct {
	MaxValueBytes         int
	MaxProfileConfigBytes int
	MaxChainBindingBytes  int
	MaxDynamicBytes       int
}

// CandidateDomainRecord is detached, untrusted ABI data from node revision
// 938fca3b7787da86827a5eb63371509b36e14761. Numeric selectors and opaque fields
// remain uninterpreted. Domain identity comes from a separately selected local
// key; the payload carries no domain ID, network, header, root or context.
// Current record fields do not authenticate historical runtime or STF execution.
type CandidateDomainRecord struct {
	DomainClass    uint8
	RuntimeKind    uint8
	StfSpecHash    chain.Hash
	InputSource    uint8
	ExecProfile    uint8
	ForeignProfile uint8
	ProfileConfig  []byte
	ChainBinding   []byte
	MinExecutors   uint8
	ProposerPolicy uint8
	FinalityModel  uint8
	Status         uint8
}

// CandidateDomainConfig is detached, untrusted data from the selected two-word
// domainConfig schema. Delays are raw uint64 values, not validated registration
// parameters, elapsed-delay observations or submission-time configuration.
type CandidateDomainConfig struct {
	WithdrawalDelay     uint64
	RuntimeUpgradeDelay uint64
}

// DecodeCandidateDomainRecord requires full unsigned widths, contiguous
// schema-ordered dynamic tails, exact offsets, zero padding and no trailing
// data. This is explicit local canonical policy, stricter than the original
// unpacker. It does not enforce RegisterDomain business rules or verify a proof.
// All structure and bounds checks precede dynamic copies; errors return no
// partial value. The caller must not mutate raw concurrently.
func DecodeCandidateDomainRecord(raw []byte, limits CandidateDomainRecordLimits) (CandidateDomainRecord, error) {
	if limits.MaxValueBytes < CandidateDomainRecordMinBytes || limits.MaxValueBytes > CandidateSMTMaxValueBytes {
		return CandidateDomainRecord{}, ErrCandidateDomainBounds
	}
	for _, cap := range [...]int{limits.MaxProfileConfigBytes, limits.MaxChainBindingBytes, limits.MaxDynamicBytes} {
		if cap <= 0 || cap > limits.MaxValueBytes {
			return CandidateDomainRecord{}, ErrCandidateDomainBounds
		}
	}
	if len(raw) > limits.MaxValueBytes {
		return CandidateDomainRecord{}, ErrCandidateDomainBounds
	}
	if len(raw) < CandidateDomainRecordMinBytes {
		return CandidateDomainRecord{}, ErrCandidateDomainEncoding
	}
	word := func(index int) []byte { return raw[index*32 : (index+1)*32] }
	// Reuse the candidate BatchEntry codec's strict unsigned-word and padding
	// primitives; neither primitive interprets the enclosing schema's semantics.
	var decoded [9]uint8
	for i, index := range [...]int{0, 1, 3, 4, 5, 8, 9, 10, 11} {
		n, ok := candidateBatchEntryUint(word(index), 1)
		if !ok {
			return CandidateDomainRecord{}, ErrCandidateDomainEncoding
		}
		decoded[i] = uint8(n)
	}
	var fields [2][]byte
	cursor, cumulative := CandidateDomainRecordHeadBytes, 0
	for i, field := range [...]struct{ index, cap int }{
		{6, limits.MaxProfileConfigBytes}, {7, limits.MaxChainBindingBytes},
	} {
		offset, ok := candidateBatchEntryUint(word(field.index), 8)
		if !ok || offset != uint64(cursor) || len(raw)-cursor < 32 {
			return CandidateDomainRecord{}, ErrCandidateDomainEncoding
		}
		n, ok := candidateBatchEntryUint(raw[cursor:cursor+32], 8)
		if !ok {
			return CandidateDomainRecord{}, ErrCandidateDomainEncoding
		}
		if n > uint64(field.cap) || n > uint64(limits.MaxDynamicBytes-cumulative) {
			return CandidateDomainRecord{}, ErrCandidateDomainBounds
		}
		start := cursor + 32
		if n > uint64(len(raw)-start) {
			return CandidateDomainRecord{}, ErrCandidateDomainEncoding
		}
		end := start + int(n) // n is bounded by a <= 4096-byte cap and the input.
		cursor = end + (-int(n) & 31)
		if cursor > len(raw) || !candidateBatchEntryZero(raw[end:cursor]) {
			return CandidateDomainRecord{}, ErrCandidateDomainEncoding
		}
		fields[i] = raw[start:end]
		cumulative += int(n)
	}
	if cursor != len(raw) {
		return CandidateDomainRecord{}, ErrCandidateDomainEncoding
	}
	value := CandidateDomainRecord{
		DomainClass: decoded[0], RuntimeKind: decoded[1], InputSource: decoded[2],
		ExecProfile: decoded[3], ForeignProfile: decoded[4], MinExecutors: decoded[5],
		ProposerPolicy: decoded[6], FinalityModel: decoded[7], Status: decoded[8],
		ProfileConfig: bytes.Clone(fields[0]), ChainBinding: bytes.Clone(fields[1]),
	}
	copy(value.StfSpecHash[:], word(2))
	return value, nil
}

// DecodeCandidateDomainConfig requires exactly two canonical uint64 ABI words.
// Fixed framing bounds the input without allocation or a configurable cap.
// Empty/truncated data, dirty upper bits and trailing bytes return no value.
func DecodeCandidateDomainConfig(raw []byte) (CandidateDomainConfig, error) {
	if len(raw) != CandidateDomainConfigBytes {
		return CandidateDomainConfig{}, ErrCandidateDomainEncoding
	}
	withdrawal, ok := candidateBatchEntryUint(raw[:32], 8)
	if !ok {
		return CandidateDomainConfig{}, ErrCandidateDomainEncoding
	}
	upgrade, ok := candidateBatchEntryUint(raw[32:], 8)
	if !ok {
		return CandidateDomainConfig{}, ErrCandidateDomainEncoding
	}
	return CandidateDomainConfig{WithdrawalDelay: withdrawal, RuntimeUpgradeDelay: upgrade}, nil
}
