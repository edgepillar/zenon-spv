// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"golang.org/x/crypto/sha3"
)

const (
	ExperimentalDomainRecordSchema = "zenon-settlement-domain-record-12/v1"
	ExperimentalDomainConfigSchema = "zenon-settlement-domain-config-2/v1"
	ExperimentalDomainRecordRule   = "zenon-phase1-domain-record/v1"
	// The selected fixed two-word config needs at most 256 encoded siblings.
	maxExperimentalDomainConfigProofBytes = 103 + proof.CandidateDomainConfigBytes + 256*32
)

var (
	ErrExperimentalBatchContextProfile = errors.New("invalid experimental three-witness profile")
	ErrExperimentalBatchContextPin     = errors.New("experimental three-witness context differs from the selected pin")
)

// ExperimentalDomainRecordPolicy selects local ABI and proof work ceilings.
// Positive byte caps do not relax the versioned rule requiring empty configs.
type ExperimentalDomainRecordPolicy struct {
	MaxProofBytes         uint32 `json:"max_proof_bytes"`
	MaxSiblings           uint16 `json:"max_siblings"`
	MaxValueBytes         uint32 `json:"max_value_bytes"`
	MaxProfileConfigBytes uint32 `json:"max_profile_config_bytes"`
	MaxChainBindingBytes  uint32 `json:"max_chain_binding_bytes"`
	MaxDynamicBytes       uint32 `json:"max_dynamic_bytes"`
}

func (p ExperimentalDomainRecordPolicy) valid() bool {
	if p.MaxProofBytes < 103+proof.CandidateDomainRecordMinBytes || p.MaxProofBytes > proof.CandidateSMTMaxProofBytes ||
		p.MaxSiblings > 256 || p.MaxValueBytes < proof.CandidateDomainRecordMinBytes || p.MaxValueBytes > proof.CandidateSMTMaxValueBytes {
		return false
	}
	for _, n := range [...]uint32{p.MaxProfileConfigBytes, p.MaxChainBindingBytes, p.MaxDynamicBytes} {
		if n == 0 || n > p.MaxValueBytes {
			return false
		}
	}
	return true
}

func (p *ExperimentalDomainRecordPolicy) UnmarshalJSON(raw []byte) error {
	var next ExperimentalDomainRecordPolicy
	if p == nil || len(raw) > 1024 || decodeRequiredObject(raw, map[string]any{
		"max_proof_bytes": &next.MaxProofBytes, "max_siblings": &next.MaxSiblings,
		"max_value_bytes": &next.MaxValueBytes, "max_profile_config_bytes": &next.MaxProfileConfigBytes,
		"max_chain_binding_bytes": &next.MaxChainBindingBytes, "max_dynamic_bytes": &next.MaxDynamicBytes,
	}) != nil || !next.valid() {
		return ErrExperimentalBatchContextProfile
	}
	*p = next
	return nil
}

func (p ExperimentalDomainRecordPolicy) abi() proof.CandidateDomainRecordLimits {
	return proof.CandidateDomainRecordLimits{MaxValueBytes: int(p.MaxValueBytes),
		MaxProfileConfigBytes: int(p.MaxProfileConfigBytes), MaxChainBindingBytes: int(p.MaxChainBindingBytes), MaxDynamicBytes: int(p.MaxDynamicBytes)}
}

type ExperimentalDomainConfigPolicy struct {
	MaxProofBytes uint32 `json:"max_proof_bytes"`
	MaxSiblings   uint16 `json:"max_siblings"`
}

func (p ExperimentalDomainConfigPolicy) valid() bool {
	return p.MaxProofBytes >= 103+proof.CandidateDomainConfigBytes && p.MaxProofBytes <= maxExperimentalDomainConfigProofBytes && p.MaxSiblings <= 256
}

func (p *ExperimentalDomainConfigPolicy) UnmarshalJSON(raw []byte) error {
	var next ExperimentalDomainConfigPolicy
	if p == nil || len(raw) > 512 || decodeRequiredObject(raw, map[string]any{
		"max_proof_bytes": &next.MaxProofBytes, "max_siblings": &next.MaxSiblings,
	}) != nil || !next.valid() {
		return ErrExperimentalBatchContextProfile
	}
	*p = next
	return nil
}

// ExperimentalBatchContextLimits caps all three proofs together. Byte caps
// must be positive; zero siblings means no siblings, never unlimited work.
type ExperimentalBatchContextLimits struct {
	MaxTotalProofBytes uint32 `json:"max_total_proof_bytes"`
	MaxTotalValueBytes uint32 `json:"max_total_value_bytes"`
	MaxTotalSiblings   uint16 `json:"max_total_siblings"`
}

func (p *ExperimentalBatchContextLimits) UnmarshalJSON(raw []byte) error {
	var next ExperimentalBatchContextLimits
	if p == nil || len(raw) > 512 || decodeRequiredObject(raw, map[string]any{
		"max_total_proof_bytes": &next.MaxTotalProofBytes, "max_total_value_bytes": &next.MaxTotalValueBytes,
		"max_total_siblings": &next.MaxTotalSiblings,
	}) != nil {
		return ErrExperimentalBatchContextProfile
	}
	*p = next // The enclosing profile checks the individual and aggregate caps.
	return nil
}

// ExperimentalBatchContextProfile is a separate versioned contract. It does
// not change the legacy single BatchEntry profile, request or fingerprint.
// Entry contains independently selected domain/runtime metadata, not proof of
// runtime identity, execution, registration delay bounds or network activation.
type ExperimentalBatchContextProfile struct {
	Version      uint32                         `json:"version"`
	Entry        ExperimentalBatchEntryProfile  `json:"entry"`
	DomainRule   string                         `json:"domain_rule"`
	DomainRecord ExperimentalDomainRecordPolicy `json:"domain_record"`
	DomainConfig ExperimentalDomainConfigPolicy `json:"domain_config"`
	Limits       ExperimentalBatchContextLimits `json:"limits"`
}

func (p ExperimentalBatchContextProfile) Validate() error {
	// Validate individual caps before adding them, including on 32-bit hosts.
	if (p.Version != 1 && p.Version != 2) || p.Entry.Version != p.Version ||
		p.Entry.Validate() != nil || p.Entry.DomainID == 0 || p.DomainRule != ExperimentalDomainRecordRule ||
		!p.DomainRecord.valid() || !p.DomainConfig.valid() {
		return ErrExperimentalBatchContextProfile
	}
	minValues := uint32(proof.CandidateBatchEntryMinBytes + proof.CandidateDomainRecordMinBytes + proof.CandidateDomainConfigBytes)
	if p.Limits.MaxTotalProofBytes < 3*103+minValues ||
		p.Limits.MaxTotalProofBytes > p.Entry.MaxProofBytes+p.DomainRecord.MaxProofBytes+p.DomainConfig.MaxProofBytes ||
		p.Limits.MaxTotalValueBytes < minValues ||
		p.Limits.MaxTotalValueBytes > p.Entry.Limits.MaxValueBytes+p.DomainRecord.MaxValueBytes+proof.CandidateDomainConfigBytes ||
		p.Limits.MaxTotalSiblings > p.Entry.MaxSiblings+p.DomainRecord.MaxSiblings+p.DomainConfig.MaxSiblings {
		return ErrExperimentalBatchContextProfile
	}
	return nil
}

func (p *ExperimentalBatchContextProfile) UnmarshalJSON(raw []byte) error {
	var next ExperimentalBatchContextProfile
	if p == nil || len(raw) > MaxExperimentalBatchEntryProfileBytes || !utf8.Valid(raw) ||
		decodeRequiredObject(raw, map[string]any{
			"version": &next.Version, "entry": &next.Entry, "domain_rule": &next.DomainRule,
			"domain_record": &next.DomainRecord, "domain_config": &next.DomainConfig, "limits": &next.Limits,
		}) != nil || next.Validate() != nil {
		return ErrExperimentalBatchContextProfile
	}
	*p = next
	return nil
}

func DecodeExperimentalBatchContextProfile(raw []byte) (ExperimentalBatchContextProfile, error) {
	var p ExperimentalBatchContextProfile
	if len(raw) > MaxExperimentalBatchEntryProfileBytes || json.Unmarshal(raw, &p) != nil {
		return ExperimentalBatchContextProfile{}, ErrExperimentalBatchContextProfile
	}
	return p, nil
}

// ExperimentalBatchContext is detached diagnostic configuration. The entry
// context binds the header/profile/source pins; this new namespace additionally
// binds both context schemas, the source rule and every individual/aggregate
// limit. Presence and canonical encoding are mandatory for every row.
type ExperimentalBatchContext struct {
	Version            uint32                         `json:"version"`
	Entry              ExperimentalBatchEntryContext  `json:"entry"`
	DomainRecordSchema string                         `json:"domain_record_schema"`
	DomainConfigSchema string                         `json:"domain_config_schema"`
	DomainRule         string                         `json:"domain_rule"`
	DomainRecord       ExperimentalDomainRecordPolicy `json:"domain_record"`
	DomainConfig       ExperimentalDomainConfigPolicy `json:"domain_config"`
	Limits             ExperimentalBatchContextLimits `json:"limits"`
	RequireCanonical   bool                           `json:"require_canonical"`
	RequirePresent     bool                           `json:"require_present"`
	Fingerprint        chain.Hash                     `json:"fingerprint"`
}

func ExperimentalBatchContextFor(state ExperimentalV3State, p ExperimentalBatchContextProfile) (ExperimentalBatchContext, error) {
	if err := p.Validate(); err != nil {
		return ExperimentalBatchContext{}, err
	}
	entry, err := ExperimentalBatchEntryContextFor(state, p.Entry)
	if err != nil {
		return ExperimentalBatchContext{}, err
	}
	c := ExperimentalBatchContext{Version: p.Version, Entry: entry, DomainRecordSchema: ExperimentalDomainRecordSchema,
		DomainConfigSchema: ExperimentalDomainConfigSchema, DomainRule: p.DomainRule, DomainRecord: p.DomainRecord,
		DomainConfig: p.DomainConfig, Limits: p.Limits, RequireCanonical: true, RequirePresent: true}
	var b bytes.Buffer
	b.WriteString("ZENON-EXPERIMENTAL-BATCH-CONTEXT\x00")
	b.WriteByte(byte(c.Version))
	b.Write(entry.Fingerprint[:])
	word := func(n uint64) { var v [8]byte; binary.BigEndian.PutUint64(v[:], n); b.Write(v[:]) }
	word(uint64(c.Version))
	for _, text := range [...]string{c.DomainRecordSchema, c.DomainConfigSchema, c.DomainRule} {
		word(uint64(len(text)))
		b.WriteString(text)
	}
	for _, n := range [...]uint64{
		uint64(p.DomainRecord.MaxProofBytes), uint64(p.DomainRecord.MaxSiblings), uint64(p.DomainRecord.MaxValueBytes),
		uint64(p.DomainRecord.MaxProfileConfigBytes), uint64(p.DomainRecord.MaxChainBindingBytes), uint64(p.DomainRecord.MaxDynamicBytes),
		uint64(p.DomainConfig.MaxProofBytes), uint64(p.DomainConfig.MaxSiblings), proof.CandidateDomainConfigBytes,
		uint64(p.Limits.MaxTotalProofBytes), uint64(p.Limits.MaxTotalValueBytes), uint64(p.Limits.MaxTotalSiblings), 1, 1,
	} {
		word(n)
	}
	c.Fingerprint = chain.Hash(sha3.Sum256(b.Bytes()))
	return c, nil
}
