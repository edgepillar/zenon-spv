// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/0x3639/zenon-spv/internal/chain"
)

var errExperimentalV3Opaque = errors.New("use experimental v3 Save or LoadTrustedExperimentalV3State instead of encoding an owned handle")

// ExperimentalV3State owns only v3 headers, under explicit non-mainnet trust
// inputs and a required finite operator-attested schedule. It is separate from
// production VerifiedState. The configured anchor is trusted; evicted ancestry,
// network activation, election, canonicality and state transitions are not proved.
// No constructor accepts a caller-built retained window or provider root.
type ExperimentalV3State struct{ data *experimentalV3StateData }

type experimentalV3StateData struct {
	config       experimentalV3Config
	headers      []chain.CandidateV3Header
	trustedLocal bool
}

func (s ExperimentalV3State) MarshalJSON() ([]byte, error) { return nil, errExperimentalV3Opaque }
func (s *ExperimentalV3State) UnmarshalJSON([]byte) error  { return errExperimentalV3Opaque }

// NewExperimentalV3State captures immutable settings and requires the selected
// context pin. Matching a pin does not authenticate its independent selection.
// The result is empty: it supplies no root until Extend succeeds.
func NewExperimentalV3State(profile ExperimentalV3Profile, policy ExperimentalV3Policy, schedule *ProducerSchedule, expected chain.Hash) (ExperimentalV3State, error) {
	c, err := freezeExperimentalV3Config(profile, policy, schedule)
	if err != nil {
		return ExperimentalV3State{}, err
	}
	if expected.IsZero() || expected != c.context.Fingerprint {
		return ExperimentalV3State{}, ErrContextFingerprintMismatch
	}
	return ExperimentalV3State{data: &experimentalV3StateData{config: c}}, nil
}

// Extend verifies the whole bounded batch before publishing a new handle.
// Failure returns the original handle. Earlier handles remain usable. Inputs
// must not be mutated concurrently while being read; their bytes are detached.
func (s ExperimentalV3State) Extend(headers []chain.CandidateV3Header) (Result, ExperimentalV3State) {
	fail := func(r Result) (Result, ExperimentalV3State) { return experimentalV3Envelope(r), s }
	if s.data == nil {
		return fail(uninitializedStateResult())
	}
	c := s.data.config
	if len(headers) == 0 {
		return fail(refuse(ReasonMissingEvidence, "no experimental v3 headers supplied"))
	}
	if uint64(len(headers)) > uint64(c.policy.MaxBatchHeaders) {
		return fail(refuse(ReasonOversizedHeaders, "experimental v3 batch exceeds configured limit"))
	}
	previous := c.profile.Anchor
	if n := len(s.data.headers); n > 0 {
		h := s.data.headers[n-1].Header
		previous = GenesisTrustRoot{ChainID: h.ChainIdentifier, Height: h.Height, HeaderHash: h.HeaderHash}
	}
	working := append(make([]chain.CandidateV3Header, 0, len(s.data.headers)+len(headers)), s.data.headers...)
	for i, incoming := range headers {
		h := cloneExperimentalV3Header(incoming)
		if r := validateExperimentalV3Header(h, c, i); r.Outcome != OutcomeAccept {
			return fail(r)
		}
		if h.Header.Height <= previous.Height || h.Header.Height-previous.Height != 1 {
			return fail(reject(ReasonHeightNonMonotonic, i, "experimental v3 header is not an immediate successor"))
		}
		if h.Header.PreviousHash != previous.HeaderHash {
			return fail(reject(ReasonBrokenLinkage, i, "experimental v3 header does not link to the owned tip"))
		}
		working = append(working, h)
		previous = GenesisTrustRoot{ChainID: h.Header.ChainIdentifier, Height: h.Header.Height, HeaderHash: h.Header.HeaderHash}
	}
	if uint64(len(working)) < c.policy.W {
		return fail(refuse(ReasonWindowNotMet, "experimental v3 retained depth is not built"))
	}
	if len(working) > int(c.policy.RetainHeaders) {
		working = append([]chain.CandidateV3Header(nil), working[len(working)-int(c.policy.RetainHeaders):]...)
	}
	next := ExperimentalV3State{data: &experimentalV3StateData{config: c, headers: working, trustedLocal: s.data.trustedLocal}}
	return next.acceptedEnvelope(), next
}

func validateExperimentalV3Header(h chain.CandidateV3Header, c experimentalV3Config, index int) Result {
	b := h.Header
	if b.Version != chain.CandidateMomentumVersion3 {
		return refuse(ReasonUnsupportedHeaderVersion, "experimental v3 state requires exactly version 3")
	}
	if b.ChainIdentifier != c.profile.Genesis.ChainID {
		return reject(ReasonChainIDMismatch, index, "experimental v3 chain differs from the configured network")
	}
	if b.Height < c.profile.FirstV3Height {
		return refuse(ReasonHeaderVersionInactive, "experimental v3 header precedes the selected first v3 height")
	}
	if b.Height <= c.profile.Anchor.Height || b.Height > c.profile.ValidThrough {
		return refuse(ReasonProtocolProfileCoverage, "experimental v3 header is outside the configured profile")
	}
	if b.NextFusionPrice < 1000 || b.NextWorkPrice < 1000 {
		return reject(ReasonInvalidResourcePrice, index, "experimental v3 resource price is below the selected node minimum")
	}
	computed, err := h.ComputeHash()
	if err != nil || computed != b.HeaderHash {
		return reject(ReasonInvalidHash, index, "experimental v3 hash differs from the signed preimage")
	}
	if len(b.PublicKey) != ed25519.PublicKeySize || len(b.Signature) != ed25519.SignatureSize || !ed25519.Verify(b.PublicKey, computed[:], b.Signature) {
		return reject(ReasonInvalidSignature, index, "experimental v3 signature does not verify")
	}
	switch NewScheduleAuthorizer(c.schedule).Authorize(b.Height, b.TimestampUnix, b.PublicKey) {
	case ProducerAuthorized:
		return accept()
	case ProducerUnauthorized:
		return reject(ReasonUnauthorizedProducer, index, "experimental v3 producer or timestamp differs from the selected schedule")
	default:
		return refuse(ReasonProducerSetUnknown, "experimental v3 producer schedule does not cover the header")
	}
}

func experimentalV3Envelope(r Result) Result {
	return r.WithNotProven(GuaranteeContentInclusion, GuaranteeCanonicality, GuaranteeStateTransition, GuaranteeStateValueInclusion)
}

func (s ExperimentalV3State) acceptedEnvelope() Result {
	r := experimentalV3Envelope(accept()).WithProven(GuaranteeHeaderChainIntegrity, GuaranteeSignatureAuthenticity, GuaranteeProducerAuthorization).
		WithTrust(TrustConfiguredAnchor, TrustExternalProtocolProfile, TrustExternalProducerSchedule)
	if s.data.trustedLocal {
		r = r.WithTrust(TrustPersistedState)
	}
	return r
}

func cloneExperimentalV3Header(h chain.CandidateV3Header) chain.CandidateV3Header {
	h.Header.PublicKey = bytes.Clone(h.Header.PublicKey)
	h.Header.Signature = bytes.Clone(h.Header.Signature)
	return h
}

func (s ExperimentalV3State) Empty() bool { return s.data == nil || len(s.data.headers) == 0 }

func (s ExperimentalV3State) Context() (ExperimentalV3Context, error) {
	if s.data == nil {
		return ExperimentalV3Context{}, ErrUninitializedState
	}
	return s.data.config.context, nil
}

func (s ExperimentalV3State) RequireContextFingerprint(expected chain.Hash) error {
	if s.data == nil {
		return ErrUninitializedState
	}
	if expected.IsZero() || expected != s.data.config.context.Fingerprint {
		return ErrContextFingerprintMismatch
	}
	return nil
}

func (s ExperimentalV3State) HeaderAtHeight(height uint64) (chain.CandidateV3Header, bool) {
	h := s.experimentalV3Header(height)
	if h == nil {
		return chain.CandidateV3Header{}, false
	}
	return cloneExperimentalV3Header(*h), true
}

// Construction/resume/extension establish contiguous private heights. Queries
// need no scan, rehash, signature work or mutable index.
func (s ExperimentalV3State) experimentalV3Header(height uint64) *chain.CandidateV3Header {
	if s.data == nil || len(s.data.headers) == 0 {
		return nil
	}
	first := s.data.headers[0].Header.Height
	if height < first || height-first >= uint64(len(s.data.headers)) {
		return nil
	}
	return &s.data.headers[int(height-first)]
}

// RootAt returns only the root in an owned accepted header, with a matching
// query context/hash and W later retained headers. This is a header-root lookup,
// not state-value proof verification or a claim of consensus finality.
func (s ExperimentalV3State) RootAt(height uint64, expectedHeader, expectedContext chain.Hash) (chain.Hash, error) {
	if err := s.RequireContextFingerprint(expectedContext); err != nil {
		return chain.Hash{}, err
	}
	h := s.experimentalV3Header(height)
	if h == nil {
		return chain.Hash{}, ErrExperimentalV3HeaderUnavailable
	}
	if expectedHeader.IsZero() || h.Header.HeaderHash != expectedHeader {
		return chain.Hash{}, ErrExperimentalV3HeaderMismatch
	}
	tip := s.data.headers[len(s.data.headers)-1].Header.Height
	if tip < height || tip-height < s.data.config.policy.W {
		return chain.Hash{}, ErrExperimentalV3Depth
	}
	return h.StateRoot, nil
}

var (
	ErrExperimentalV3HeaderUnavailable = errors.New("experimental v3 header is not retained")
	ErrExperimentalV3HeaderMismatch    = errors.New("experimental v3 query hash differs from the owned header")
	ErrExperimentalV3Depth             = errors.New("experimental v3 query lacks the configured retained depth")
)
