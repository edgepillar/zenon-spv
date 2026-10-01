package verify

import "errors"

// MaxRetainHeaders bounds explicitly selected history independently of W.
const MaxRetainHeaders = 4096

var ErrInvalidRetentionPolicy = errors.New("retention requires W < K <= 4096; zero selects legacy retention")

// Policy carries the verifier's risk-tier and resource bounds.
//
// W is the policy window depth from
// zenon-spv-vault/spec/spv-implementation-guide.md §2.3:
// the verifier returns REFUSED if fewer than W consecutive headers
// have been verified beyond the queried height.
//
// The Max* fields are DoS guardrails (loose upper bounds) introduced
// by Branch 2b. They are NOT typical-case sizing; legitimate traffic
// will not approach them. Empirical justification lives in
// docs/resource-bound-measurements.md. A zero value disables the
// corresponding bound (back-compat for tests; production builds
// should always set non-zero defaults via DefaultPolicy /
// PolicyForTier).
//
// Type convention: W is uint64 because spec §2.3 expresses the
// policy window depth as an unsigned protocol parameter and because
// callers compare it against header heights (also uint64). The
// Max* count caps are int because they bound slice lengths (Go
// slice indexing is int, and len() returns int). The two types
// intentionally differ — do not force one to the other; bridging
// happens at the call site (uint64(len(slice)) for the few places
// that compare a slice length against W).
type Policy struct {
	// ProtocolProfile is an explicit operator-attested activation policy.
	// Nil preserves legacy v1-only verification without an activation claim.
	ProtocolProfile *ProtocolProfile

	W uint64 // policy-window depth in headers

	// RetainHeaders is K, the maximum number of retained headers. Zero keeps
	// legacy W+1 storage. Explicit K must exceed W and be at most 4096.
	RetainHeaders int

	// Per-bundle wire-format cap. Enforced at JSON load time via
	// proof.LoadHeaderBundleWithLimits (io.LimitReader). 0 disables.
	MaxBundleBytes int64

	// Per-call cap on header count. Enforced inside VerifyHeaders and
	// during CLI bundle decoding.
	// 0 disables.
	MaxHeaders int

	// Cap on the number of CommitmentEvidence entries in a bundle or a
	// VerifySegment call. Enforced during CLI bundle decoding and before
	// commitment indexing/evaluation.
	// 0 disables.
	MaxCommitments int

	// Per-commitment cap on the number of AccountHeaders inside one
	// FlatContentEvidence. Enforced during CLI decoding, inside VerifyCommitment,
	// and by the commitment batch preflight used by VerifySegment and the CLI.
	// 0 disables.
	MaxFlatEvidenceMembers int

	// Aggregate cap across ALL commitments in a bundle or VerifySegment call.
	// Repeated references count separately, including unused targets. Defends
	// against the n × m flood (many commitments × many members each)
	// that the per-commitment cap alone misses. 0 disables.
	// CLI decoding also counts replaced nested arrays against this cap.
	MaxTotalFlatEvidenceMembers int

	// Per-bundle cap on the number of AccountSegment entries.
	// Enforced during CLI bundle decoding and preflight. 0 disables.
	MaxSegments int

	// Per-segment cap on the number of AccountBlocks. Enforced
	// during CLI decoding and inside VerifySegment via a synthetic REFUSED
	// result. 0 disables.
	MaxSegmentBlocks int

	// Aggregate cap on AccountBlocks across all segments. Same
	// defense-in-depth shape as MaxTotalFlatEvidenceMembers. 0
	// disables.
	// CLI decoding also counts replaced nested arrays against this cap.
	MaxTotalSegmentBlocks int

	// Per-bundle cap on the number of StateValueProof entries
	// (state-proof PR / Phase 2). Enforced during CLI bundle decoding and
	// preflight. The proof package's own DecodeLimits keeps policy wiring
	// outside the parser without a package cycle. 0 disables.
	MaxStateValueProofs int

	// Per-state-proof cap on len(ProofNodes) (count). Enforced
	// during CLI decoding and inside VerifyStateValue. 0 disables.
	MaxStateProofNodes int

	// Per-state-proof cap on sum(len(node)) across ProofNodes
	// (byte total). Distinct from MaxStateProofNodes because a
	// count-only cap is bypassable by one huge node. Enforced
	// during CLI decoding and inside VerifyStateValue. Repeated proof-node
	// arrays consume the same byte budget during decoding. 0 disables.
	MaxStateProofBytes int
}

// ValidateRetention checks depth/capacity before allocation or truncation.
func (p Policy) ValidateRetention() error {
	if p.W >= uint64(MaxPersistedHeaders) || p.RetainHeaders < 0 || p.RetainHeaders > MaxRetainHeaders ||
		(p.RetainHeaders != 0 && uint64(p.RetainHeaders) <= p.W) {
		return ErrInvalidRetentionPolicy
	}
	return nil
}

// Window-tier constants per spec §2.3:
//
//	Low    — 6 subsequent headers
//	Medium — 60 subsequent headers
//	High   — 360 subsequent headers
//
// These are local depth policies, not settlement or finality guarantees.
const (
	WindowLow    uint64 = 6
	WindowMedium uint64 = 60
	WindowHigh   uint64 = 360
)

// Bound defaults shipped by DefaultPolicy and PolicyForTier. See
// docs/resource-bound-measurements.md for the empirical rationale.
const (
	DefaultMaxBundleBytes              int64 = 64 * 1024 * 1024 // 64 MiB
	DefaultMaxHeaders                  int   = 100_000
	DefaultMaxCommitments              int   = 10_000
	DefaultMaxFlatEvidenceMembers      int   = 100_000
	DefaultMaxTotalFlatEvidenceMembers int   = 1_000_000
	DefaultMaxSegments                 int   = 1_000
	DefaultMaxSegmentBlocks            int   = 10_000
	DefaultMaxTotalSegmentBlocks       int   = 100_000

	// State-proof caps (state-proof PR / Phase 2). Conservative
	// initial defaults — every StateCommitmentKind currently
	// REFUSES, so these only gate how much malformed/oversized
	// input the verifier accepts before refusing on shape. Tune
	// down once a real accepting kind exists with measured proof
	// sizes (see docs/resource-bound-measurements.md for the
	// pattern from Branch 2b).
	DefaultMaxStateValueProofs int = 1_000
	DefaultMaxStateProofNodes  int = 1_024
	DefaultMaxStateProofBytes  int = 4 * 1024 * 1024 // 4 MiB per proof
)

// DefaultPolicy returns the conservative default (Low tier, full
// resource bounds set). Callers should override W per use case
// but typically inherit the Max* defaults.
func DefaultPolicy() Policy {
	return policyWithDefaults(WindowLow)
}

// PolicyForTier selects a Policy from a string tier name. Unknown
// names fall through to the low tier. All tiers carry the same
// resource bounds; the tier only affects W.
func PolicyForTier(tier string) Policy {
	switch tier {
	case "high":
		return policyWithDefaults(WindowHigh)
	case "medium":
		return policyWithDefaults(WindowMedium)
	default:
		return policyWithDefaults(WindowLow)
	}
}

func policyWithDefaults(w uint64) Policy {
	return Policy{
		W:                           w,
		MaxBundleBytes:              DefaultMaxBundleBytes,
		MaxHeaders:                  DefaultMaxHeaders,
		MaxCommitments:              DefaultMaxCommitments,
		MaxFlatEvidenceMembers:      DefaultMaxFlatEvidenceMembers,
		MaxTotalFlatEvidenceMembers: DefaultMaxTotalFlatEvidenceMembers,
		MaxSegments:                 DefaultMaxSegments,
		MaxSegmentBlocks:            DefaultMaxSegmentBlocks,
		MaxTotalSegmentBlocks:       DefaultMaxTotalSegmentBlocks,
		MaxStateValueProofs:         DefaultMaxStateValueProofs,
		MaxStateProofNodes:          DefaultMaxStateProofNodes,
		MaxStateProofBytes:          DefaultMaxStateProofBytes,
	}
}
