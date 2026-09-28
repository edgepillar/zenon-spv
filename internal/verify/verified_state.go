package verify

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

// VerifiedState owns an immutable retained window and its verification options.
// Construct it from an explicit anchor or a trusted local state file. There is
// deliberately no constructor accepting a caller-built HeaderState. The zero
// value cannot verify or save. This establishes API provenance, not consensus
// canonicality or the authenticity of a supplied anchor or local file.
type VerifiedState struct {
	data *verifiedStateData
}

type verifiedStateData struct {
	state        HeaderState
	opts         VerifyOptions
	trustedLocal bool
}

var ErrUninitializedState = errors.New("verified state is not initialized")

var errOpaqueStateEncoding = errors.New("use Save or LoadTrustedState instead of encoding VerifiedState directly")

func (s VerifiedState) MarshalJSON() ([]byte, error) { return nil, errOpaqueStateEncoding }

func (s *VerifiedState) UnmarshalJSON([]byte) error { return errOpaqueStateEncoding }

// StateAuthorizationError preserves the tri-state result when a trusted local
// window cannot be re-authorized under the requested producer policy.
type StateAuthorizationError struct {
	Result Result
}

func (e *StateAuthorizationError) Error() string {
	return fmt.Sprintf("persisted state did not re-authorize under configured schedule: %s", e.Result)
}

// NewVerifiedState starts an empty window under explicit trust inputs. Header
// verification must succeed before this handle contains any evidence.
func NewVerifiedState(anchor GenesisTrustRoot, opts VerifyOptions) (VerifiedState, error) {
	opts, err := freezeStateOptions(anchor, opts)
	if err != nil {
		return VerifiedState{}, err
	}
	return VerifiedState{data: &verifiedStateData{state: NewHeaderState(anchor, opts.Policy), opts: opts}}, nil
}

// LoadTrustedState loads a trusted local file, or initializes an empty state
// when the file is absent. The caller must protect the file's provenance.
// Integrity, anchor/profile matching, and retained producer authorization are
// rechecked; evicted ancestry and file authenticity cannot be reconstructed.
func LoadTrustedState(path string, anchor GenesisTrustRoot, opts VerifyOptions) (VerifiedState, error) {
	if path == "" {
		return VerifiedState{}, errors.New("trusted state path is empty")
	}
	opts, err := freezeStateOptions(anchor, opts)
	if err != nil {
		return VerifiedState{}, err
	}
	state, err := LoadOrInit(path, anchor, opts.Policy)
	if err != nil {
		return VerifiedState{}, err
	}
	if r := AuthorizeRetainedWindow(state, opts); r.Outcome != OutcomeAccept {
		return VerifiedState{}, &StateAuthorizationError{Result: r}
	}
	return VerifiedState{data: &verifiedStateData{state: state, opts: opts, trustedLocal: !state.Empty()}}, nil
}

// Extend returns a new handle only after ACCEPT. Failure returns the original
// handle. Inputs may be reused or mutated after the call returns. Callers must
// not mutate inputs concurrently while verification is reading them.
func (s VerifiedState) Extend(headers []chain.Header) (Result, VerifiedState) {
	if s.data == nil {
		return uninitializedStateResult(), s
	}
	r, next := VerifyHeadersWithOptions(headers, s.data.state, s.data.opts)
	if r.Outcome != OutcomeAccept {
		return r, s
	}
	return s.withStateTrust(r), VerifiedState{data: &verifiedStateData{
		state: cloneHeaderState(next), opts: s.data.opts, trustedLocal: s.data.trustedLocal,
	}}
}

// VerifyCommitment uses the same policy that created this state; a query cannot
// lower the depth requirement or replace its activation profile.
func (s VerifiedState) VerifyCommitment(evidence proof.CommitmentEvidence) Result {
	if s.data == nil {
		return uninitializedStateResult()
	}
	return s.withStateTrust(VerifyCommitment(s.data.state, evidence, s.data.opts.Policy))
}

func (s VerifiedState) VerifySegment(segment proof.AccountSegment, commitments []proof.CommitmentEvidence) SegmentResult {
	if s.data == nil {
		return SegmentResult{Blocks: []Result{uninitializedStateResult()}}
	}
	r := VerifySegment(s.data.state, segment, commitments, s.data.opts.Policy)
	for i := range r.Blocks {
		r.Blocks[i] = s.withStateTrust(r.Blocks[i])
	}
	return r
}

func (s VerifiedState) VerifyStateValue(evidence proof.StateValueProof) Result {
	if s.data == nil {
		return uninitializedStateResult()
	}
	return s.withStateTrust(VerifyStateValue(s.data.state, evidence, s.data.opts.Policy))
}

func (s VerifiedState) Empty() bool { return s.data == nil || s.data.state.Empty() }

// TrustAssumptions describes captured external inputs without making a proof
// claim. The returned slice is detached from the handle.
func (s VerifiedState) TrustAssumptions() []TrustAssumption {
	if s.data == nil {
		return nil
	}
	return withProtocolTrust(s.withStateTrust(accept()), s.data.state.ProtocolProfile).TrustAssumptions
}

// Tip and Snapshot return detached copies, including key/signature slices and
// the protocol profile. Snapshot is for inspection or persistence adapters;
// mutating or deserializing one cannot construct another VerifiedState.
func (s VerifiedState) Tip() (chain.Header, bool) {
	if s.data == nil {
		return chain.Header{}, false
	}
	h, ok := s.data.state.Tip()
	return cloneStateHeader(h), ok
}

func (s VerifiedState) Snapshot() HeaderState {
	if s.data == nil {
		return HeaderState{}
	}
	return cloneHeaderState(s.data.state)
}

func (s VerifiedState) Save(path string) error {
	if s.data == nil {
		return ErrUninitializedState
	}
	return SaveHeaderState(path, s.data.state)
}

func uninitializedStateResult() Result {
	return refuse(ReasonUninitializedState, ErrUninitializedState.Error())
}

func (s VerifiedState) withStateTrust(r Result) Result {
	if r.Outcome != OutcomeAccept {
		return r
	}
	r = r.WithTrust(TrustConfiguredAnchor)
	if s.data.trustedLocal {
		r = r.WithTrust(TrustPersistedState)
	}
	if s.data.opts.ProducerAuth.Mode == ProducerAuthRequired &&
		s.data.opts.ProducerAuth.Authorizer.Source() == ProducerSourceOperatorAttested {
		r = r.WithTrust(TrustExternalProducerSchedule)
	}
	return r
}

func cloneStateHeader(h chain.Header) chain.Header {
	h.PublicKey = bytes.Clone(h.PublicKey)
	h.Signature = bytes.Clone(h.Signature)
	return h
}

func cloneHeaderState(s HeaderState) HeaderState {
	s.ProtocolProfile = cloneProtocolProfile(s.ProtocolProfile)
	window := make([]chain.Header, len(s.RetainedWindow))
	for i, h := range s.RetainedWindow {
		window[i] = cloneStateHeader(h)
	}
	s.RetainedWindow = window
	return s
}

func freezeStateOptions(anchor GenesisTrustRoot, opts VerifyOptions) (VerifyOptions, error) {
	if err := anchor.Validate(); err != nil {
		return VerifyOptions{}, fmt.Errorf("%w: %v", ErrInvalidRetainedState, err)
	}
	if opts.Policy.W >= uint64(MaxPersistedHeaders) {
		return VerifyOptions{}, fmt.Errorf("%w: policy window exceeds persistence limit", ErrInvalidRetainedState)
	}
	limits := []int64{opts.Policy.MaxBundleBytes, int64(opts.Policy.MaxHeaders), int64(opts.Policy.MaxCommitments),
		int64(opts.Policy.MaxFlatEvidenceMembers), int64(opts.Policy.MaxTotalFlatEvidenceMembers),
		int64(opts.Policy.MaxSegments), int64(opts.Policy.MaxSegmentBlocks), int64(opts.Policy.MaxTotalSegmentBlocks),
		int64(opts.Policy.MaxStateValueProofs), int64(opts.Policy.MaxStateProofNodes), int64(opts.Policy.MaxStateProofBytes)}
	for _, limit := range limits {
		if limit < 0 {
			return VerifyOptions{}, errors.New("policy resource limits must not be negative")
		}
	}
	opts.Policy.ProtocolProfile = cloneProtocolProfile(opts.Policy.ProtocolProfile)
	if err := validateProfileAnchor(opts.Policy.ProtocolProfile, anchor); err != nil {
		return VerifyOptions{}, err
	}
	if err := opts.ProducerAuth.validate(); err != nil {
		return VerifyOptions{}, err
	}
	if opts.ProducerAuth.Mode == ProducerAuthRequired {
		auth := opts.ProducerAuth.Authorizer
		if a, ok := auth.(*ScheduleAuthorizer); ok {
			if a == nil || a.Schedule == nil {
				return VerifyOptions{}, errors.New("producer schedule is nil")
			}
			if err := validateScheduleSize(a.Schedule.Coverage, a.Schedule.Entries); err != nil {
				return VerifyOptions{}, err
			}
			// Only substantive schedule fields are used for authorization.
			// Rebuild the index after copying; never retain caller-owned maps.
			schedule := &ProducerSchedule{ChainID: a.Schedule.ChainID, ScheduleHash: a.Schedule.ScheduleHash,
				Coverage: append([]ProducerCoverage(nil), a.Schedule.Coverage...),
				Entries:  append([]ProducerEntry(nil), a.Schedule.Entries...)}
			if schedule.ChainID != anchor.ChainID {
				return VerifyOptions{}, errors.New("producer schedule chain ID differs from configured anchor")
			}
			if err := schedule.Validate(); err != nil {
				return VerifyOptions{}, err
			}
			auth = NewScheduleAuthorizer(schedule)
		}
		source := auth.Source()
		if source != ProducerSourceOperatorAttested && source != ProducerSourceLocallyDerivedFromChain {
			return VerifyOptions{}, fmt.Errorf("unsupported source %d for required producer authorization", source)
		}
		opts.ProducerAuth.Authorizer = isolatedStateAuthorizer{delegate: auth, source: source}
	}
	return opts, nil
}

// Custom authorizers remain trusted behavior supplied by the caller and must
// be stable and concurrency-safe when shared. They receive disposable key
// copies so retaining or changing callback arguments cannot mutate state.
type isolatedStateAuthorizer struct {
	delegate ProducerAuthorizer
	source   ProducerSource
}

func (a isolatedStateAuthorizer) Authorize(height, timestamp uint64, key []byte) ProducerDecision {
	return a.delegate.Authorize(height, timestamp, bytes.Clone(key))
}

func (a isolatedStateAuthorizer) Source() ProducerSource { return a.source }
