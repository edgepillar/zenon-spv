// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"golang.org/x/crypto/sha3"
)

var (
	ErrExperimentalBatchContextOpaque       = errors.New("experimental three-witness handles cannot be encoded or supplied by a caller")
	ErrExperimentalBatchContextRequiredRows = errors.New("a required three-witness row is absent")
	ErrExperimentalDomainRecordRule         = errors.New("domain record differs from the selected phase1 source rule")
)

// ExperimentalBatchContextRequest has the same local selectors as the legacy
// request, but Context must be the independently selected three-witness pin.
type ExperimentalBatchContextRequest ExperimentalBatchEntryRequest

func (r *ExperimentalBatchContextRequest) UnmarshalJSON(raw []byte) error {
	if r == nil {
		return ErrExperimentalBatchEntryRequest
	}
	next, err := DecodeExperimentalBatchEntryRequest(raw)
	if err != nil {
		return err
	}
	*r = ExperimentalBatchContextRequest(next)
	return nil
}

func DecodeExperimentalBatchContextRequest(raw []byte) (ExperimentalBatchContextRequest, error) {
	next, err := DecodeExperimentalBatchEntryRequest(raw)
	return ExperimentalBatchContextRequest(next), err
}

type ExperimentalBatchContextProofs struct {
	BatchEntry   []byte
	DomainRecord []byte
	DomainConfig []byte
}

type ExperimentalBatchContextWitnesses struct {
	BatchEntry   proof.CandidateStateWitness
	DomainRecord proof.CandidateStateWitness
	DomainConfig proof.CandidateStateWitness
}

// ExperimentalBatchContextQuery owns an immutable header state and explicit
// policy. Diagnostic contexts, provider roots and retained projections cannot
// construct a query. This does not enable production state-value acceptance.
type ExperimentalBatchContextQuery struct{ data *experimentalBatchContextData }
type experimentalBatchContextData struct {
	entry   ExperimentalBatchEntryQuery
	profile ExperimentalBatchContextProfile
	context ExperimentalBatchContext
}

func (q ExperimentalBatchContextQuery) MarshalJSON() ([]byte, error) {
	return nil, ErrExperimentalBatchContextOpaque
}
func (q *ExperimentalBatchContextQuery) UnmarshalJSON([]byte) error {
	return ErrExperimentalBatchContextOpaque
}

func NewExperimentalBatchContextQuery(state ExperimentalV3State, p ExperimentalBatchContextProfile, expected chain.Hash) (ExperimentalBatchContextQuery, error) {
	c, err := ExperimentalBatchContextFor(state, p)
	if err != nil {
		return ExperimentalBatchContextQuery{}, err
	}
	if expected.IsZero() || expected != c.Fingerprint {
		return ExperimentalBatchContextQuery{}, ErrExperimentalBatchContextPin
	}
	entry, err := NewExperimentalBatchEntryQuery(state, p.Entry, c.Entry.Fingerprint)
	if err != nil {
		return ExperimentalBatchContextQuery{}, err
	}
	return ExperimentalBatchContextQuery{data: &experimentalBatchContextData{entry: entry, profile: p, context: c}}, nil
}

func (q ExperimentalBatchContextQuery) Context() (ExperimentalBatchContext, error) {
	if q.data == nil {
		return ExperimentalBatchContext{}, ErrUninitializedState
	}
	return q.data.context, nil
}

type experimentalBatchContextBinding struct {
	entry                  experimentalBatchEntryBinding
	recordKey, configKey   [27]byte
	recordPath, configPath chain.Hash
	request                ExperimentalBatchContextRequest
	fingerprint            chain.Hash
}

func (q ExperimentalBatchContextQuery) binding(request ExperimentalBatchContextRequest) (experimentalBatchContextBinding, error) {
	if q.data == nil {
		return experimentalBatchContextBinding{}, ErrUninitializedState
	}
	if request.Context.IsZero() || request.Context != q.data.context.Fingerprint {
		return experimentalBatchContextBinding{}, ErrExperimentalBatchContextPin
	}
	// Reuse the exact H/hash/tip checks and the single owned RootAt lookup.
	// The provider never supplies either context or a key/path to this step.
	selected := ExperimentalBatchEntryRequest(request)
	selected.Context = q.data.context.Entry.Fingerprint
	entry, err := q.data.entry.binding(selected)
	if err != nil {
		return experimentalBatchContextBinding{}, err
	}
	p := q.data.profile.Entry
	record := proof.CandidateSettlementDomainRecordKey(p.Settlement, p.DomainID)
	config := proof.CandidateSettlementDomainConfigKey(p.Settlement, p.DomainID)
	var identity bytes.Buffer
	identity.WriteString("ZENON-EXPERIMENTAL-BATCH-CONTEXT-QUERY\x00\x01")
	identity.Write(q.data.context.Fingerprint[:])
	identity.Write(entry.fingerprint[:])
	return experimentalBatchContextBinding{entry: entry, recordKey: record, configKey: config,
		recordPath: chain.Hash(sha3.Sum256(record[:])), configPath: chain.Hash(sha3.Sum256(config[:])),
		request: request, fingerprint: chain.Hash(sha3.Sum256(identity.Bytes()))}, nil
}

type ExperimentalBatchContextMembership struct {
	LedgerKey string     `json:"ledger_key"`
	Path      chain.Hash `json:"path"`
	Value     []byte     `json:"value"`
	ValueSHA3 chain.Hash `json:"value_sha3_256"`
	ProofSHA3 chain.Hash `json:"proof_sha3_256"`
}

// ExperimentalBatchContextResult contains three rows at exactly the same H,
// header hash and root, under the explicit configured-header trust assumptions.
// Current config is not submission-time config. No field establishes runtime
// execution, W depth, consensus finality, funds release or recipient receive.
// This detached data is not an opaque query/state handle.
type ExperimentalBatchContextResult struct {
	Scope            string                             `json:"scope"`
	Context          ExperimentalBatchContext           `json:"context"`
	Request          ExperimentalBatchContextRequest    `json:"request"`
	QueryFingerprint chain.Hash                         `json:"query_fingerprint"`
	Root             chain.Hash                         `json:"root"`
	BatchMembership  ExperimentalBatchContextMembership `json:"batch_membership"`
	RecordMembership ExperimentalBatchContextMembership `json:"record_membership"`
	ConfigMembership ExperimentalBatchContextMembership `json:"config_membership"`
	Entry            proof.CandidateBatchEntry          `json:"entry"`
	DomainRecord     proof.CandidateDomainRecord        `json:"domain_record"`
	DomainConfig     proof.CandidateDomainConfig        `json:"domain_config"`
	HeaderTrust      []TrustAssumption                  `json:"header_trust"`
}

func (r ExperimentalBatchContextResult) MarshalJSON() ([]byte, error) {
	if !utf8.ValidString(r.Entry.ExecutorPillar) {
		return nil, ErrExperimentalBatchEntryJSON
	}
	type wire ExperimentalBatchContextResult
	return json.Marshal(wire(r))
}

func (q ExperimentalBatchContextQuery) Query(request ExperimentalBatchContextRequest, raw ExperimentalBatchContextProofs) (ExperimentalBatchContextResult, error) {
	binding, err := q.binding(request)
	if err != nil {
		return ExperimentalBatchContextResult{}, err
	}
	return q.read(binding, raw)
}

func (q ExperimentalBatchContextQuery) read(b experimentalBatchContextBinding, raw ExperimentalBatchContextProofs) (ExperimentalBatchContextResult, error) {
	p := q.data.profile
	matches, err := proof.ReadCandidateSMTProofSet(b.entry.root, []proof.CandidateSMTProofInput{
		{Path: b.entry.path, Proof: raw.BatchEntry, Limits: proof.CandidateSMTLimits{MaxProofBytes: int(p.Entry.MaxProofBytes), MaxValueBytes: int(p.Entry.Limits.MaxValueBytes)}, MaxSiblings: int(p.Entry.MaxSiblings)},
		{Path: b.recordPath, Proof: raw.DomainRecord, Limits: proof.CandidateSMTLimits{MaxProofBytes: int(p.DomainRecord.MaxProofBytes), MaxValueBytes: int(p.DomainRecord.MaxValueBytes)}, MaxSiblings: int(p.DomainRecord.MaxSiblings)},
		{Path: b.configPath, Proof: raw.DomainConfig, Limits: proof.CandidateSMTLimits{MaxProofBytes: int(p.DomainConfig.MaxProofBytes), MaxValueBytes: proof.CandidateDomainConfigBytes}, MaxSiblings: int(p.DomainConfig.MaxSiblings)},
	}, proof.CandidateSMTSetLimits{MaxProofs: 3, MaxTotalProofBytes: int(p.Limits.MaxTotalProofBytes),
		MaxTotalValueBytes: int(p.Limits.MaxTotalValueBytes), MaxTotalSiblings: int(p.Limits.MaxTotalSiblings)})
	if err != nil {
		return ExperimentalBatchContextResult{}, err
	}
	if err := requireExperimentalBatchContextRows(matches); err != nil {
		return ExperimentalBatchContextResult{}, err
	}
	entry, err := proof.DecodeCandidateBatchEntry(matches[0].Value, p.Entry.Limits.abi())
	if err != nil {
		return ExperimentalBatchContextResult{}, err
	}
	if err := experimentalBatchEntrySourceRule(entry, p.Entry.SourceRule); err != nil {
		return ExperimentalBatchContextResult{}, err
	}
	record, err := proof.DecodeCandidateDomainRecord(matches[1].Value, p.DomainRecord.abi())
	if err != nil {
		return ExperimentalBatchContextResult{}, err
	}
	if !experimentalPhase1DomainRecord(record) {
		return ExperimentalBatchContextResult{}, ErrExperimentalDomainRecordRule
	}
	config, err := proof.DecodeCandidateDomainConfig(matches[2].Value)
	if err != nil {
		return ExperimentalBatchContextResult{}, err
	}
	membership := func(key []byte, path chain.Hash, match proof.CandidateSMTMatch, encoded []byte) ExperimentalBatchContextMembership {
		return ExperimentalBatchContextMembership{LedgerKey: hex.EncodeToString(key), Path: path,
			Value: match.Value, ValueSHA3: chain.Hash(sha3.Sum256(match.Value)), ProofSHA3: chain.Hash(sha3.Sum256(encoded))}
	}
	return ExperimentalBatchContextResult{
		Scope: "EXPERIMENTAL_CONFIGURED_HEADER_THREE_ROW_MEMBERSHIP", Context: q.data.context, Request: b.request,
		QueryFingerprint: b.fingerprint, Root: b.entry.root,
		BatchMembership:  membership(b.entry.key[:], b.entry.path, matches[0], raw.BatchEntry),
		RecordMembership: membership(b.recordKey[:], b.recordPath, matches[1], raw.DomainRecord),
		ConfigMembership: membership(b.configKey[:], b.configPath, matches[2], raw.DomainConfig),
		Entry:            entry, DomainRecord: record, DomainConfig: config,
		HeaderTrust: q.data.entry.data.state.acceptedEnvelope().TrustAssumptions,
	}, nil
}

// Missing supporting context must never become the legacy single-row
// "BatchEntry absent" signal. Only a complete present canonical set can reach
// typed decoding. The matches come exclusively from the mathematical checker;
// this policy helper grants no root, key or header authority by itself.
func requireExperimentalBatchContextRows(matches []proof.CandidateSMTMatch) error {
	if len(matches) != 3 {
		return proof.ErrCandidateSMTEncoding
	}
	for _, match := range matches {
		if !match.Canonical {
			return ErrExperimentalBatchEntryCanonical
		}
		if !match.Present {
			return ErrExperimentalBatchContextRequiredRows
		}
	}
	return nil
}

// The explicit phase1 source rule does not claim all RegisterDomain checks:
// build/network-dependent delay bounds and historical context remain separate.
func experimentalPhase1DomainRecord(r proof.CandidateDomainRecord) bool {
	return r.DomainClass == 0 && r.RuntimeKind == 0 && r.InputSource == 0 && r.ExecProfile == 0 && r.ForeignProfile == 0 &&
		r.MinExecutors == 1 && r.ProposerPolicy == 0 && r.FinalityModel == 0 && r.Status <= 1 &&
		len(r.ProfileConfig) == 0 && len(r.ChainBinding) == 0
}

// QueryWitnesses bounds provider hints together before checking them. It uses
// only the owned header root, requires exact proven-value equality for every
// hint and returns no partial result on any error. Missing RPC results must be
// refused by the transport; zero witnesses never mean proven absence.
func (q ExperimentalBatchContextQuery) QueryWitnesses(request ExperimentalBatchContextRequest, witnesses ExperimentalBatchContextWitnesses) (ExperimentalBatchContextResult, error) {
	b, err := q.binding(request)
	if err != nil {
		return ExperimentalBatchContextResult{}, err
	}
	p := q.data.profile
	remaining := int(p.Limits.MaxTotalValueBytes)
	for i, hint := range [...]proof.CandidateStateWitness{witnesses.BatchEntry, witnesses.DomainRecord, witnesses.DomainConfig} {
		cap := [...]int{int(p.Entry.Limits.MaxValueBytes), int(p.DomainRecord.MaxValueBytes), proof.CandidateDomainConfigBytes}[i]
		if len(hint.Value) > cap || len(hint.Value) > remaining {
			return ExperimentalBatchContextResult{}, proof.ErrCandidateSMTBounds
		}
		remaining -= len(hint.Value)
		if hint.Root != b.entry.root {
			return ExperimentalBatchContextResult{}, ErrExperimentalBatchEntryWitnessRoot
		}
	}
	result, err := q.read(b, ExperimentalBatchContextProofs{witnesses.BatchEntry.Proof, witnesses.DomainRecord.Proof, witnesses.DomainConfig.Proof})
	if err != nil {
		return ExperimentalBatchContextResult{}, err
	}
	if !bytes.Equal(result.BatchMembership.Value, witnesses.BatchEntry.Value) ||
		!bytes.Equal(result.RecordMembership.Value, witnesses.DomainRecord.Value) ||
		!bytes.Equal(result.ConfigMembership.Value, witnesses.DomainConfig.Value) {
		return ExperimentalBatchContextResult{}, ErrExperimentalBatchEntryWitnessValue
	}
	return result, nil
}

// CompareGateway is only stored-field equality on detached result data. It
// neither verifies this receiver nor changes proof validity. A differing newer
// frontier leaves the historical three-row result intact; isFinalized remains
// an unauthenticated provider hint in both cases.
func (r ExperimentalBatchContextResult) CompareGateway(gateway proof.CandidateSettlementBatch) ExperimentalBatchEntryGatewayComparison {
	return ExperimentalBatchEntryGatewayComparison{
		StoredFieldsMatch:       sameExperimentalBatchEntryGateway(r.Context.Entry.DomainID, r.Request.BatchID, r.Entry, gateway),
		FrontierIsFinalizedHint: gateway.IsFinalized,
	}
}
