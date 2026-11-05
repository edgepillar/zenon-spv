// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"golang.org/x/crypto/sha3"
)

const (
	ExperimentalBatchEntrySchema           = "zenon-settlement-batch-entry-17/v1"
	ExperimentalBatchEntryExecutorRevision = "caeaf764270b1489a53c860c6006026af208f924"
	ExperimentalBatchEntrySDKRevision      = "bc1548d75473797f24bb3eb79f5594969c596e39"
	ExperimentalBatchEntrySettlementHex    = "01b3b6e5adcb4d0cad7fcef33598c6318c6318c0"
	MaxExperimentalBatchEntryProfileBytes  = 16 * 1024
)

var (
	ErrExperimentalBatchEntryProfile = errors.New("invalid experimental BatchEntry profile")
	ErrExperimentalBatchEntryContext = errors.New("experimental BatchEntry context differs from the selected pin")
)

// ExperimentalBatchEntrySettlementAddress returns a value copy of the selected
// source constant. The source pin does not authenticate a running network.
func ExperimentalBatchEntrySettlementAddress() chain.Address {
	var address chain.Address
	_, _ = hex.Decode(address[:], []byte(ExperimentalBatchEntrySettlementHex))
	return address
}

// ExperimentalBatchEntryLimits selects local work and string interpretation.
// These are not network limits. Zero byte limits never disable a cap.
type ExperimentalBatchEntryLimits struct {
	MaxValueBytes            uint32                              `json:"max_value_bytes"`
	MaxExecutorPillarBytes   uint32                              `json:"max_executor_pillar_bytes"`
	MaxAssetFlowSummaryBytes uint32                              `json:"max_asset_flow_summary_bytes"`
	MaxProofDataBytes        uint32                              `json:"max_proof_data_bytes"`
	MaxDynamicBytes          uint32                              `json:"max_dynamic_bytes"`
	StringRule               proof.CandidateBatchEntryStringRule `json:"string_rule"`
}

func (v ExperimentalBatchEntryLimits) validate() error {
	if v.MaxValueBytes < proof.CandidateBatchEntryMinBytes || v.MaxValueBytes > proof.CandidateSMTMaxValueBytes ||
		(v.StringRule != proof.CandidateBatchEntryOpaqueString && v.StringRule != proof.CandidateBatchEntryUTF8String) {
		return ErrExperimentalBatchEntryProfile
	}
	for _, n := range []uint32{v.MaxExecutorPillarBytes, v.MaxAssetFlowSummaryBytes, v.MaxProofDataBytes, v.MaxDynamicBytes} {
		if n == 0 || n > v.MaxValueBytes {
			return ErrExperimentalBatchEntryProfile
		}
	}
	return nil
}

func (v *ExperimentalBatchEntryLimits) UnmarshalJSON(raw []byte) error {
	var next ExperimentalBatchEntryLimits
	if v == nil || len(raw) > 1024 {
		return ErrExperimentalBatchEntryProfile
	}
	if decodeRequiredObject(raw, map[string]any{
		"max_value_bytes":              &next.MaxValueBytes,
		"max_executor_pillar_bytes":    &next.MaxExecutorPillarBytes,
		"max_asset_flow_summary_bytes": &next.MaxAssetFlowSummaryBytes,
		"max_proof_data_bytes":         &next.MaxProofDataBytes,
		"max_dynamic_bytes":            &next.MaxDynamicBytes,
		"string_rule":                  &next.StringRule,
	}) != nil || next.validate() != nil {
		return ErrExperimentalBatchEntryProfile
	}
	*v = next
	return nil
}

func (v ExperimentalBatchEntryLimits) abi() proof.CandidateBatchEntryLimits {
	return proof.CandidateBatchEntryLimits{
		MaxValueBytes: int(v.MaxValueBytes), MaxExecutorPillarBytes: int(v.MaxExecutorPillarBytes),
		MaxAssetFlowSummaryBytes: int(v.MaxAssetFlowSummaryBytes), MaxProofDataBytes: int(v.MaxProofDataBytes),
		MaxDynamicBytes: int(v.MaxDynamicBytes), StringRule: v.StringRule,
	}
}

// ExperimentalBatchEntryProfile binds the local key domain and strict ABI/work
// policy. RuntimeIdentity is independently selected metadata about the exact
// domain/runtime contract, not an authenticated runtime or execution proof.
// Both versions require canonical SMT encodings and the selected Settlement
// source constant. Version 2 additionally selects an explicit source-field rule;
// version 1 retains its original ABI-only interpretation.
type ExperimentalBatchEntryProfile struct {
	Version         uint32                       `json:"version"`
	Settlement      chain.Address                `json:"settlement"`
	DomainID        uint32                       `json:"domain_id"`
	RuntimeIdentity chain.Hash                   `json:"runtime_identity"`
	MaxProofBytes   uint32                       `json:"max_proof_bytes"`
	MaxSiblings     uint16                       `json:"max_siblings"`
	Limits          ExperimentalBatchEntryLimits `json:"limits"`
	Source          string                       `json:"source"`
	SourceRule      string                       `json:"source_rule,omitempty"`
}

func (p ExperimentalBatchEntryProfile) Validate() error {
	if !((p.Version == 1 && p.SourceRule == "") || (p.Version == 2 && p.SourceRule == ExperimentalBatchEntrySourceRule)) ||
		p.Settlement != ExperimentalBatchEntrySettlementAddress() || p.RuntimeIdentity.IsZero() ||
		p.MaxProofBytes < 103+proof.CandidateBatchEntryMinBytes || p.MaxProofBytes > proof.CandidateSMTMaxProofBytes ||
		p.MaxSiblings > 256 || p.Limits.validate() != nil || len(p.Source) > 1024 ||
		strings.TrimSpace(p.Source) == "" || !utf8.ValidString(p.Source) {
		return ErrExperimentalBatchEntryProfile
	}
	for _, r := range p.Source {
		if unicode.IsControl(r) {
			return ErrExperimentalBatchEntryProfile
		}
	}
	return nil
}

func (p ExperimentalBatchEntryProfile) MarshalJSON() ([]byte, error) {
	type wire struct {
		Version         uint32                       `json:"version"`
		Settlement      string                       `json:"settlement"`
		DomainID        uint32                       `json:"domain_id"`
		RuntimeIdentity chain.Hash                   `json:"runtime_identity"`
		MaxProofBytes   uint32                       `json:"max_proof_bytes"`
		MaxSiblings     uint16                       `json:"max_siblings"`
		Limits          ExperimentalBatchEntryLimits `json:"limits"`
		Source          string                       `json:"source"`
		SourceRule      string                       `json:"source_rule,omitempty"`
	}
	return json.Marshal(wire{p.Version, hex.EncodeToString(p.Settlement[:]), p.DomainID, p.RuntimeIdentity, p.MaxProofBytes, p.MaxSiblings, p.Limits, p.Source, p.SourceRule})
}

func (p *ExperimentalBatchEntryProfile) UnmarshalJSON(raw []byte) error {
	if p == nil || len(raw) > MaxExperimentalBatchEntryProfileBytes || !utf8.Valid(raw) {
		return ErrExperimentalBatchEntryProfile
	}
	var next ExperimentalBatchEntryProfile
	var address, runtime string
	// This bounded probe only selects the exact schema. The strict pass below
	// still rejects duplicates, case aliases, nulls and all unknown fields.
	var probe struct {
		Version uint32 `json:"version"`
	}
	if json.Unmarshal(raw, &probe) != nil || (probe.Version != 1 && probe.Version != 2) {
		return ErrExperimentalBatchEntryProfile
	}
	fields := map[string]any{
		"version": &next.Version, "settlement": &address, "domain_id": &next.DomainID, "runtime_identity": &runtime,
		"max_proof_bytes": &next.MaxProofBytes, "max_siblings": &next.MaxSiblings, "limits": &next.Limits, "source": &next.Source,
	}
	if probe.Version == 2 {
		fields["source_rule"] = &next.SourceRule
	}
	if decodeRequiredObject(raw, fields) != nil {
		return ErrExperimentalBatchEntryProfile
	}
	if len(address) != 40 || len(runtime) != 64 {
		return ErrExperimentalBatchEntryProfile
	}
	if _, err := hex.Decode(next.Settlement[:], []byte(address)); err != nil || hex.EncodeToString(next.Settlement[:]) != address {
		return ErrExperimentalBatchEntryProfile
	}
	if _, err := hex.Decode(next.RuntimeIdentity[:], []byte(runtime)); err != nil || hex.EncodeToString(next.RuntimeIdentity[:]) != runtime {
		return ErrExperimentalBatchEntryProfile
	}
	if next.Validate() != nil {
		return ErrExperimentalBatchEntryProfile
	}
	*p = next
	return nil
}

// DecodeExperimentalBatchEntryProfile bounds the complete document including
// whitespace. Decoding a policy supplies no header or state-value authority.
func DecodeExperimentalBatchEntryProfile(raw []byte) (ExperimentalBatchEntryProfile, error) {
	var p ExperimentalBatchEntryProfile
	if len(raw) > MaxExperimentalBatchEntryProfileBytes || json.Unmarshal(raw, &p) != nil {
		return ExperimentalBatchEntryProfile{}, ErrExperimentalBatchEntryProfile
	}
	return p, nil
}

// ExperimentalBatchEntryContext is detached diagnostic configuration. Matching
// pins do not authenticate its independent selection or the selected runtime.
// The static context excludes tip/history; every query binds their exact IDs.
type ExperimentalBatchEntryContext struct {
	Version          uint32                       `json:"version"`
	Header           ExperimentalV3Context        `json:"header"`
	Schema           string                       `json:"schema"`
	ExecutorRevision string                       `json:"executor_revision"`
	SDKRevision      string                       `json:"sdk_revision"`
	Settlement       chain.Address                `json:"settlement"`
	DomainID         uint32                       `json:"domain_id"`
	RuntimeIdentity  chain.Hash                   `json:"runtime_identity"`
	MaxProofBytes    uint32                       `json:"max_proof_bytes"`
	MaxSiblings      uint16                       `json:"max_siblings"`
	Limits           ExperimentalBatchEntryLimits `json:"limits"`
	RequireCanonical bool                         `json:"require_canonical"`
	Fingerprint      chain.Hash                   `json:"fingerprint"`
	SourceRule       string                       `json:"source_rule,omitempty"`
}

func ExperimentalBatchEntryContextFor(state ExperimentalV3State, p ExperimentalBatchEntryProfile) (ExperimentalBatchEntryContext, error) {
	if err := p.Validate(); err != nil {
		return ExperimentalBatchEntryContext{}, err
	}
	header, err := state.Context()
	if err != nil {
		return ExperimentalBatchEntryContext{}, err
	}
	if header.NodeRevision != ExperimentalV3NodeRevision {
		return ExperimentalBatchEntryContext{}, ErrExperimentalBatchEntryProfile
	}
	c := ExperimentalBatchEntryContext{Version: p.Version, Header: header, Schema: ExperimentalBatchEntrySchema,
		ExecutorRevision: ExperimentalBatchEntryExecutorRevision, SDKRevision: ExperimentalBatchEntrySDKRevision,
		Settlement: p.Settlement, DomainID: p.DomainID, RuntimeIdentity: p.RuntimeIdentity,
		MaxProofBytes: p.MaxProofBytes, MaxSiblings: p.MaxSiblings, Limits: p.Limits, RequireCanonical: true, SourceRule: p.SourceRule}
	var b bytes.Buffer
	b.WriteString("ZENON-EXPERIMENTAL-BATCH-ENTRY\x00")
	b.WriteByte(byte(c.Version))
	word := func(n uint64) { var v [8]byte; binary.BigEndian.PutUint64(v[:], n); b.Write(v[:]) }
	word(uint64(c.Version))
	b.Write(header.Fingerprint[:])
	for _, revision := range []string{header.NodeRevision, c.ExecutorRevision, c.SDKRevision} {
		raw, _ := hex.DecodeString(revision)
		b.Write(raw)
	}
	word(uint64(len(c.Schema)))
	b.WriteString(c.Schema)
	b.Write(c.Settlement[:])
	var domain [4]byte
	binary.BigEndian.PutUint32(domain[:], c.DomainID)
	b.Write(domain[:])
	b.Write(c.RuntimeIdentity[:])
	for _, n := range []uint64{uint64(c.MaxProofBytes), uint64(c.MaxSiblings), 1, uint64(c.Limits.MaxValueBytes),
		uint64(c.Limits.MaxExecutorPillarBytes), uint64(c.Limits.MaxAssetFlowSummaryBytes), uint64(c.Limits.MaxProofDataBytes),
		uint64(c.Limits.MaxDynamicBytes), uint64(c.Limits.StringRule)} {
		word(n)
	}
	if c.Version == 2 {
		word(uint64(len(c.SourceRule)))
		b.WriteString(c.SourceRule)
	}
	c.Fingerprint = chain.Hash(sha3.Sum256(b.Bytes()))
	return c, nil
}
