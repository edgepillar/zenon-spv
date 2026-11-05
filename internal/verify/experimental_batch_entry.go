// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"golang.org/x/crypto/sha3"
)

var (
	ErrExperimentalBatchEntryOpaque       = errors.New("experimental BatchEntry query handles cannot be encoded or supplied by a caller")
	ErrExperimentalBatchEntryRequest      = errors.New("invalid experimental BatchEntry request")
	ErrExperimentalBatchEntryTip          = errors.New("experimental BatchEntry request differs from the owned tip")
	ErrExperimentalBatchEntryCanonical    = errors.New("experimental BatchEntry requires a canonical proof")
	ErrExperimentalBatchEntryAbsent       = errors.New("no typed BatchEntry value is present in this proof")
	ErrExperimentalBatchEntryWitnessRoot  = errors.New("candidate witness root differs from the owned header")
	ErrExperimentalBatchEntryWitnessValue = errors.New("candidate witness value differs from the root-proven value")
	ErrExperimentalBatchEntryGateway      = errors.New("candidate gateway fields differ from the selected proven row")
	ErrExperimentalBatchEntryJSON         = errors.New("opaque executor-pillar bytes require an explicit lossless output encoding")
)

// ExperimentalBatchEntryRequest is selected locally, including the static
// typed-query context and exact owned tip. BatchID is not learned from a proof.
type ExperimentalBatchEntryRequest struct {
	Context    chain.Hash `json:"context"`
	Height     uint64     `json:"height"`
	HeaderHash chain.Hash `json:"header_hash"`
	TipHeight  uint64     `json:"tip_height"`
	TipHash    chain.Hash `json:"tip_hash"`
	BatchID    uint64     `json:"batch_id"`
}

func (r *ExperimentalBatchEntryRequest) UnmarshalJSON(raw []byte) error {
	if r == nil || len(raw) > 2048 || !utf8.Valid(raw) {
		return ErrExperimentalBatchEntryRequest
	}
	var next ExperimentalBatchEntryRequest
	var context, header, tip string
	if decodeRequiredObject(raw, map[string]any{
		"context": &context, "height": &next.Height, "header_hash": &header,
		"tip_height": &next.TipHeight, "tip_hash": &tip, "batch_id": &next.BatchID,
	}) != nil {
		return ErrExperimentalBatchEntryRequest
	}
	for _, pair := range []struct {
		text   string
		target *chain.Hash
	}{{context, &next.Context}, {header, &next.HeaderHash}, {tip, &next.TipHash}} {
		if len(pair.text) != 64 {
			return ErrExperimentalBatchEntryRequest
		}
		if _, err := hex.Decode(pair.target[:], []byte(pair.text)); err != nil || hex.EncodeToString(pair.target[:]) != pair.text || pair.target.IsZero() {
			return ErrExperimentalBatchEntryRequest
		}
	}
	if next.Height == 0 || next.TipHeight == 0 {
		return ErrExperimentalBatchEntryRequest
	}
	*r = next
	return nil
}

func DecodeExperimentalBatchEntryRequest(raw []byte) (ExperimentalBatchEntryRequest, error) {
	var request ExperimentalBatchEntryRequest
	if len(raw) > 2048 || json.Unmarshal(raw, &request) != nil {
		return ExperimentalBatchEntryRequest{}, ErrExperimentalBatchEntryRequest
	}
	return request, nil
}

// ExperimentalBatchEntryQuery captures one immutable owned state and policy.
// No constructor accepts a raw root, diagnostic context or retained window.
type ExperimentalBatchEntryQuery struct {
	data *experimentalBatchEntryQueryData
}
type experimentalBatchEntryQueryData struct {
	state   ExperimentalV3State
	profile ExperimentalBatchEntryProfile
	context ExperimentalBatchEntryContext
}

func (q ExperimentalBatchEntryQuery) MarshalJSON() ([]byte, error) {
	return nil, ErrExperimentalBatchEntryOpaque
}
func (q *ExperimentalBatchEntryQuery) UnmarshalJSON([]byte) error {
	return ErrExperimentalBatchEntryOpaque
}

func NewExperimentalBatchEntryQuery(state ExperimentalV3State, p ExperimentalBatchEntryProfile, expected chain.Hash) (ExperimentalBatchEntryQuery, error) {
	context, err := ExperimentalBatchEntryContextFor(state, p)
	if err != nil {
		return ExperimentalBatchEntryQuery{}, err
	}
	if expected.IsZero() || expected != context.Fingerprint {
		return ExperimentalBatchEntryQuery{}, ErrExperimentalBatchEntryContext
	}
	if state.Empty() {
		return ExperimentalBatchEntryQuery{}, ErrExperimentalV3HeaderUnavailable
	}
	return ExperimentalBatchEntryQuery{data: &experimentalBatchEntryQueryData{state: state, profile: p, context: context}}, nil
}

func (q ExperimentalBatchEntryQuery) Context() (ExperimentalBatchEntryContext, error) {
	if q.data == nil {
		return ExperimentalBatchEntryContext{}, ErrUninitializedState
	}
	return q.data.context, nil
}

type experimentalBatchEntryBinding struct {
	request     ExperimentalBatchEntryRequest
	root        chain.Hash
	key         [35]byte
	path        chain.Hash
	fingerprint chain.Hash
}

func (q ExperimentalBatchEntryQuery) binding(request ExperimentalBatchEntryRequest) (experimentalBatchEntryBinding, error) {
	if q.data == nil {
		return experimentalBatchEntryBinding{}, ErrUninitializedState
	}
	if request.Context.IsZero() || request.Context != q.data.context.Fingerprint {
		return experimentalBatchEntryBinding{}, ErrExperimentalBatchEntryContext
	}
	headers := q.data.state.data.headers
	tip := headers[len(headers)-1].Header
	if request.TipHeight == 0 || request.TipHash.IsZero() || request.TipHeight != tip.Height || request.TipHash != tip.HeaderHash {
		return experimentalBatchEntryBinding{}, ErrExperimentalBatchEntryTip
	}
	root, err := q.data.state.RootAt(request.Height, request.HeaderHash, q.data.context.Header.Fingerprint)
	if err != nil {
		return experimentalBatchEntryBinding{}, err
	}
	p := q.data.profile
	key := proof.CandidateSettlementBatchEntryKey(p.Settlement, p.DomainID, request.BatchID)
	path := chain.Hash(sha3.Sum256(key[:]))
	var b bytes.Buffer
	b.WriteString("ZENON-EXPERIMENTAL-BATCH-ENTRY-QUERY\x00\x01")
	b.Write(q.data.context.Fingerprint[:])
	word := func(n uint64) { var v [8]byte; binary.BigEndian.PutUint64(v[:], n); b.Write(v[:]) }
	word(request.Height)
	b.Write(request.HeaderHash[:])
	word(request.TipHeight)
	b.Write(request.TipHash[:])
	word(request.BatchID)
	return experimentalBatchEntryBinding{request: request, root: root, key: key, path: path, fingerprint: chain.Hash(sha3.Sum256(b.Bytes()))}, nil
}

// ExperimentalBatchEntryResult is detached read-only consumer data. Its scope
// is membership under the configured owned header, not production acceptance,
// canonicality, consensus finality, STF correctness or funds/receive status.
// Editing or decoding a result never creates a query/state handle.
type ExperimentalBatchEntryResult struct {
	Scope            string                                   `json:"scope"`
	Context          ExperimentalBatchEntryContext            `json:"context"`
	Request          ExperimentalBatchEntryRequest            `json:"request"`
	QueryFingerprint chain.Hash                               `json:"query_fingerprint"`
	Root             chain.Hash                               `json:"root"`
	LedgerKey        string                                   `json:"ledger_key"`
	Path             chain.Hash                               `json:"path"`
	Value            []byte                                   `json:"value"`
	ValueSHA3        chain.Hash                               `json:"value_sha3_256"`
	ProofSHA3        chain.Hash                               `json:"proof_sha3_256"`
	Entry            proof.CandidateBatchEntry                `json:"entry"`
	HeaderTrust      []TrustAssumption                        `json:"header_trust"`
	Gateway          *ExperimentalBatchEntryGatewayComparison `json:"gateway,omitempty"`
}

// MarshalJSON refuses lossy replacement of opaque non-UTF-8 ABI strings.
// Go consumers can still use the original bytes and explicit hex/binary output.
func (r ExperimentalBatchEntryResult) MarshalJSON() ([]byte, error) {
	if !utf8.ValidString(r.Entry.ExecutorPillar) {
		return nil, ErrExperimentalBatchEntryJSON
	}
	type wire ExperimentalBatchEntryResult
	return json.Marshal(wire(r))
}

// Query verifies a raw proof against the owned header root and local key. The
// proof's stored value is the output, not a predetermined gateway answer.
// Inputs must not be mutated concurrently while being read.
func (q ExperimentalBatchEntryQuery) Query(request ExperimentalBatchEntryRequest, raw []byte) (ExperimentalBatchEntryResult, error) {
	binding, err := q.binding(request)
	if err != nil {
		return ExperimentalBatchEntryResult{}, err
	}
	return q.read(binding, raw)
}

func (q ExperimentalBatchEntryQuery) read(binding experimentalBatchEntryBinding, raw []byte) (ExperimentalBatchEntryResult, error) {
	p := q.data.profile
	match, entry, err := readExperimentalBatchEntry(binding.root, binding.path, raw, p)
	if err != nil {
		return ExperimentalBatchEntryResult{}, err
	}
	return ExperimentalBatchEntryResult{
		Scope: "EXPERIMENTAL_CONFIGURED_HEADER_MEMBERSHIP", Context: q.data.context, Request: binding.request,
		QueryFingerprint: binding.fingerprint, Root: binding.root, LedgerKey: hex.EncodeToString(binding.key[:]), Path: binding.path,
		Value: match.Value, ValueSHA3: chain.Hash(sha3.Sum256(match.Value)), ProofSHA3: chain.Hash(sha3.Sum256(raw)), Entry: entry,
		HeaderTrust: q.data.state.acceptedEnvelope().TrustAssumptions,
	}, nil
}

// This is a pure composition step. Its tests can use mathematical fixtures;
// they do not create or qualify an owned header. Only binding supplies a root
// to this helper in the exported API.
func readExperimentalBatchEntry(root, path chain.Hash, raw []byte, p ExperimentalBatchEntryProfile) (proof.CandidateSMTMatch, proof.CandidateBatchEntry, error) {
	if len(raw) > int(p.MaxProofBytes) || (len(raw) >= 99 && binary.BigEndian.Uint16(raw[97:99]) > p.MaxSiblings) {
		return proof.CandidateSMTMatch{}, proof.CandidateBatchEntry{}, proof.ErrCandidateSMTBounds
	}
	match, err := proof.ReadCandidateSMTProof(root, path, raw, proof.CandidateSMTLimits{MaxProofBytes: int(p.MaxProofBytes), MaxValueBytes: int(p.Limits.MaxValueBytes)})
	if err != nil {
		return proof.CandidateSMTMatch{}, proof.CandidateBatchEntry{}, err
	}
	if !match.Canonical {
		return proof.CandidateSMTMatch{}, proof.CandidateBatchEntry{}, ErrExperimentalBatchEntryCanonical
	}
	if !match.Present {
		return proof.CandidateSMTMatch{}, proof.CandidateBatchEntry{}, ErrExperimentalBatchEntryAbsent
	}
	entry, err := proof.DecodeCandidateBatchEntry(match.Value, p.Limits.abi())
	if err != nil {
		return proof.CandidateSMTMatch{}, proof.CandidateBatchEntry{}, err
	}
	if err := experimentalBatchEntrySourceRule(entry, p.SourceRule); err != nil {
		return proof.CandidateSMTMatch{}, proof.CandidateBatchEntry{}, err
	}
	return match, entry, nil
}

// QueryWitness treats the RPC's root/value as consistency hints. Its root is
// never used to choose the verification root. A nil/missing RPC result must be
// refused by the transport rather than supplied as an application absence.
func (q ExperimentalBatchEntryQuery) QueryWitness(request ExperimentalBatchEntryRequest, witness proof.CandidateStateWitness) (ExperimentalBatchEntryResult, error) {
	binding, err := q.binding(request)
	if err != nil {
		return ExperimentalBatchEntryResult{}, err
	}
	if len(witness.Value) > int(q.data.profile.Limits.MaxValueBytes) || len(witness.Proof) > int(q.data.profile.MaxProofBytes) {
		return ExperimentalBatchEntryResult{}, proof.ErrCandidateSMTBounds
	}
	if witness.Root != binding.root {
		return ExperimentalBatchEntryResult{}, ErrExperimentalBatchEntryWitnessRoot
	}
	result, err := q.read(binding, witness.Proof)
	if err != nil {
		return ExperimentalBatchEntryResult{}, err
	}
	if !bytes.Equal(result.Value, witness.Value) {
		return ExperimentalBatchEntryResult{}, ErrExperimentalBatchEntryWitnessValue
	}
	return result, nil
}

// ExperimentalBatchEntryGatewayComparison compares stored fields only. The
// frontier boolean is retained as an untrusted hint, never imported as a fact
// at H, W depth, consensus finality, funds release or recipient receive.
type ExperimentalBatchEntryGatewayComparison struct {
	StoredFieldsMatch             bool `json:"stored_fields_match"`
	FrontierIsFinalizedHint       bool `json:"frontier_is_finalized_hint"`
	FrontierIdentityAuthenticated bool `json:"frontier_identity_authenticated"`
}

func (q ExperimentalBatchEntryQuery) QueryWithGateway(request ExperimentalBatchEntryRequest, witness proof.CandidateStateWitness, gateway proof.CandidateSettlementBatch) (ExperimentalBatchEntryResult, error) {
	result, err := q.QueryWitness(request, witness)
	if err != nil {
		return ExperimentalBatchEntryResult{}, err
	}
	if !sameExperimentalBatchEntryGateway(q.data.profile.DomainID, request.BatchID, result.Entry, gateway) {
		return ExperimentalBatchEntryResult{}, ErrExperimentalBatchEntryGateway
	}
	result.Gateway = &ExperimentalBatchEntryGatewayComparison{StoredFieldsMatch: true, FrontierIsFinalizedHint: gateway.IsFinalized}
	return result, nil
}

func sameExperimentalBatchEntryGateway(domain uint32, batch uint64, entry proof.CandidateBatchEntry, gateway proof.CandidateSettlementBatch) bool {
	return gateway.DomainID == domain && gateway.BatchID == batch && sameExperimentalBatchEntry(entry, gateway.Entry)
}

func sameExperimentalBatchEntry(a, b proof.CandidateBatchEntry) bool {
	return a.ProtocolVersion == b.ProtocolVersion && a.FirstInputSeq == b.FirstInputSeq && a.LastInputSeq == b.LastInputSeq &&
		a.PreStateRoot == b.PreStateRoot && a.PostStateRoot == b.PostStateRoot && a.InputRoot == b.InputRoot &&
		a.ReceiptRoot == b.ReceiptRoot && a.EventRoot == b.EventRoot && a.OutboxRoot == b.OutboxRoot && a.DaHash == b.DaHash &&
		a.DaMode == b.DaMode && a.ExecutorPillar == b.ExecutorPillar && a.SubmittedAtHeight == b.SubmittedAtHeight &&
		a.FinalizeAtHeight == b.FinalizeAtHeight && bytes.Equal(a.AssetFlowSummary, b.AssetFlowSummary) &&
		bytes.Equal(a.ProofData, b.ProofData) && a.State == b.State
}
