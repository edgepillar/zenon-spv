package verify

import (
	"encoding/binary"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// VerificationContext describes captured verification settings without free-form
// provenance metadata. It is a diagnostic value, not evidence or a state handle.
// Its fingerprint excludes profile Source, peer metadata, files, retained
// history, and the verifier binary. Equal fingerprints do not authenticate
// inputs or imply that two state files can be used interchangeably.
type VerificationContext struct {
	SchemaVersion     uint32                `json:"schema_version"`
	Fingerprint       *chain.Hash           `json:"fingerprint"`
	FingerprintStatus string                `json:"fingerprint_status"`
	Anchor            GenesisTrustRoot      `json:"anchor"`
	Policy            ContextPolicy         `json:"policy"`
	ProtocolProfile   *ContextProtocolRules `json:"protocol_profile"`
	Producer          ContextProducer       `json:"producer"`
	Checkpoints       []Checkpoint          `json:"checkpoints"`
}

// ContextPolicy includes every captured resource and depth limit. Zero resource
// limits retain their disabled meaning. A context does not assert that every
// operation enforces every limit; aggregate bundle checks remain in the CLI.
type ContextPolicy struct {
	W                           uint64 `json:"w"`
	RetainHeaders               int64  `json:"retain_headers,omitempty"`
	MaxBundleBytes              int64  `json:"max_bundle_bytes"`
	MaxHeaders                  int64  `json:"max_headers"`
	MaxCommitments              int64  `json:"max_commitments"`
	MaxFlatEvidenceMembers      int64  `json:"max_flat_evidence_members"`
	MaxTotalFlatEvidenceMembers int64  `json:"max_total_flat_evidence_members"`
	MaxSegments                 int64  `json:"max_segments"`
	MaxSegmentBlocks            int64  `json:"max_segment_blocks"`
	MaxTotalSegmentBlocks       int64  `json:"max_total_segment_blocks"`
	MaxStateValueProofs         int64  `json:"max_state_value_proofs"`
	MaxStateProofNodes          int64  `json:"max_state_proof_nodes"`
	MaxStateProofBytes          int64  `json:"max_state_proof_bytes"`
}

// ContextProtocolRules omits the free-form Source label entirely, including
// from the fingerprint. The profile's anchor is the context's validated anchor.
// Nil means legacy v1-only behavior without an activation assertion.
type ContextProtocolRules struct {
	Version      uint32 `json:"version"`
	ValidThrough uint64 `json:"valid_through"`
	V2FromHeight uint64 `json:"v2_from_height"`
}

type ContextProducer struct {
	Mode         string      `json:"mode"`
	Source       string      `json:"source"`
	Kind         string      `json:"kind"` // disabled, schedule, or custom
	ScheduleHash *chain.Hash `json:"schedule_hash"`
}

var (
	ErrContextFingerprintMismatch    = errors.New("verification context fingerprint does not match the expected settings")
	ErrContextFingerprintUnavailable = errors.New("verification context fingerprint is unavailable")
)

// RequireContextFingerprint checks the settings owned by this handle, never a
// caller-supplied diagnostic object. Matching settings do not authenticate the
// anchor, schedule, activation, saved history, peers, or verifier executable.
func (s VerifiedState) RequireContextFingerprint(expected chain.Hash) error {
	c, err := s.VerificationContext()
	if err != nil {
		return err
	}
	if c.Fingerprint == nil || c.FingerprintStatus != "available" {
		return ErrContextFingerprintUnavailable
	}
	if *c.Fingerprint != expected {
		return ErrContextFingerprintMismatch
	}
	return nil
}

// VerificationContext returns detached settings, including the applicable
// embedded checkpoints. A required custom authorizer has no reproducible
// behavior identity, so its fingerprint is null with an explicit status.
// The zero handle returns ErrUninitializedState without producing a context.
func (s VerifiedState) VerificationContext() (VerificationContext, error) {
	if s.data == nil {
		return VerificationContext{}, ErrUninitializedState
	}
	p := s.data.opts.Policy
	c := VerificationContext{
		SchemaVersion: 1, FingerprintStatus: "available",
		Anchor: s.data.state.Genesis,
		Policy: ContextPolicy{
			W: p.W, MaxBundleBytes: p.MaxBundleBytes, MaxHeaders: int64(p.MaxHeaders),
			MaxCommitments: int64(p.MaxCommitments), MaxFlatEvidenceMembers: int64(p.MaxFlatEvidenceMembers),
			MaxTotalFlatEvidenceMembers: int64(p.MaxTotalFlatEvidenceMembers), MaxSegments: int64(p.MaxSegments),
			MaxSegmentBlocks: int64(p.MaxSegmentBlocks), MaxTotalSegmentBlocks: int64(p.MaxTotalSegmentBlocks),
			MaxStateValueProofs: int64(p.MaxStateValueProofs), MaxStateProofNodes: int64(p.MaxStateProofNodes),
			MaxStateProofBytes: int64(p.MaxStateProofBytes),
		},
		Producer:    ContextProducer{Mode: ProducerAuthDisabled.String(), Source: ProducerSourceNone.String(), Kind: "disabled"},
		Checkpoints: []Checkpoint{},
	}
	if p.RetainHeaders != 0 {
		c.SchemaVersion, c.Policy.RetainHeaders = 2, int64(p.RetainHeaders)
	}
	if p.ProtocolProfile != nil {
		profile := p.ProtocolProfile
		c.ProtocolProfile = &ContextProtocolRules{Version: profile.Version,
			ValidThrough: profile.ValidThrough, V2FromHeight: profile.V2FromHeight}
	}
	if c.Anchor.ChainID == MainnetChainID {
		c.Checkpoints = MainnetCheckpoints()
	}
	if s.data.opts.ProducerAuth.Mode == ProducerAuthRequired {
		// freezeStateOptions captures this wrapper. Do not invoke caller
		// callbacks or trust a custom author's claim to provide a schedule hash.
		a := s.data.opts.ProducerAuth.Authorizer.(isolatedStateAuthorizer)
		c.Producer = ContextProducer{Mode: ProducerAuthRequired.String(), Source: a.source.String(), Kind: "custom"}
		if schedule, ok := a.delegate.(*ScheduleAuthorizer); ok {
			hash := schedule.Schedule.ScheduleHash
			c.Producer.Kind, c.Producer.ScheduleHash = "schedule", &hash
		} else {
			c.FingerprintStatus = "unavailable_custom_authorizer"
			return c, nil
		}
	}
	fingerprint := contextFingerprint(c)
	c.Fingerprint = &fingerprint
	return c, nil
}

// VerificationContextJSON encodes the diagnostic context as a single JSON
// object. It never includes paths, profile Source, or schedule peer metadata.
func (s VerifiedState) VerificationContextJSON() ([]byte, error) {
	c, err := s.VerificationContext()
	if err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

// contextFingerprint uses a versioned, domain-separated binary encoding,
// specified in docs/verification-context.md. Never hash the JSON presentation:
// whitespace and object-key ordering must not change the settings identity.
func contextFingerprint(c VerificationContext) chain.Hash {
	d := sha3.New256()
	if c.SchemaVersion == 2 {
		d.Write([]byte("zenon-spv/verification-context/v2\x00"))
	} else {
		d.Write([]byte("zenon-spv/verification-context/v1\x00"))
	}
	var buf [8]byte
	u64 := func(v uint64) {
		binary.BigEndian.PutUint64(buf[:], v)
		d.Write(buf[:])
	}
	text := func(v string) { u64(uint64(len(v))); d.Write([]byte(v)) }
	u64(uint64(c.SchemaVersion))
	u64(c.Anchor.ChainID)
	u64(c.Anchor.Height)
	d.Write(c.Anchor.HeaderHash[:])
	p := c.Policy
	u64(p.W)
	if c.SchemaVersion == 2 {
		u64(uint64(p.RetainHeaders))
	}
	for _, v := range []int64{p.MaxBundleBytes, p.MaxHeaders, p.MaxCommitments, p.MaxFlatEvidenceMembers,
		p.MaxTotalFlatEvidenceMembers, p.MaxSegments, p.MaxSegmentBlocks, p.MaxTotalSegmentBlocks,
		p.MaxStateValueProofs, p.MaxStateProofNodes, p.MaxStateProofBytes} {
		u64(uint64(v)) // Constructors have already refused negative limits.
	}
	if c.ProtocolProfile == nil {
		u64(0)
	} else {
		u64(1)
		u64(uint64(c.ProtocolProfile.Version))
		u64(c.ProtocolProfile.ValidThrough)
		u64(c.ProtocolProfile.V2FromHeight)
	}
	text(c.Producer.Mode)
	text(c.Producer.Source)
	text(c.Producer.Kind)
	if c.Producer.ScheduleHash == nil {
		u64(0)
	} else {
		u64(1)
		d.Write(c.Producer.ScheduleHash[:])
	}
	u64(uint64(len(c.Checkpoints)))
	for _, cp := range c.Checkpoints {
		u64(cp.Height)
		d.Write(cp.HeaderHash[:])
	}
	var out chain.Hash
	copy(out[:], d.Sum(nil))
	return out
}
