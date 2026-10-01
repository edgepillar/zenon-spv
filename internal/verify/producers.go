package verify

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// ProducerDecision is the tri-state result of producer authorization.
//
// Per docs/producer-set-verification.md §4:
//   - Authorized: header.PublicKey derives to the schedule-expected
//     producing address AND header.TimestampUnix matches the
//     schedule's recorded slot timestamp.
//   - Unauthorized: schedule covers the header's height but either the
//     timestamp or the derived address disagrees.
//   - Unknown: no schedule interval covers the header's height. The
//     verifier MUST NOT extrapolate.
//
// Callers map decisions to verifier outcomes:
//
//	Unauthorized -> REJECT / ReasonUnauthorizedProducer
//	Unknown      -> REFUSED / ReasonProducerSetUnknown
type ProducerDecision int

const (
	ProducerAuthorized ProducerDecision = iota
	ProducerUnauthorized
	ProducerSetUnknown
)

// String renders the decision for diagnostic output.
func (d ProducerDecision) String() string {
	switch d {
	case ProducerAuthorized:
		return "Authorized"
	case ProducerUnauthorized:
		return "Unauthorized"
	case ProducerSetUnknown:
		return "ProducerSetUnknown"
	default:
		return fmt.Sprintf("ProducerDecision(%d)", int(d))
	}
}

// ProducerSource describes where the verifier's producer schedule
// came from. Drives the CLI caveat tier:
//
//	None                       -> tier 1 (no authorizer; "not enforced")
//	OperatorAttested           -> tier 2 (snapshot schedule; not canonical-chain)
//	LocallyDerivedFromChain    -> no schedule-source caveat (future phase)
type ProducerSource int

const (
	ProducerSourceNone ProducerSource = iota
	ProducerSourceOperatorAttested
	ProducerSourceLocallyDerivedFromChain
)

// String renders the source for diagnostic output.
func (s ProducerSource) String() string {
	switch s {
	case ProducerSourceNone:
		return "None"
	case ProducerSourceOperatorAttested:
		return "OperatorAttested"
	case ProducerSourceLocallyDerivedFromChain:
		return "LocallyDerivedFromChain"
	default:
		return fmt.Sprintf("ProducerSource(%d)", int(s))
	}
}

// ProducerAuthMode selects whether the verifier enforces producer
// authorization. Required with a nil Authorizer is a deliberate
// REFUSED-everything mode — it must NOT silently downgrade.
type ProducerAuthMode int

const (
	ProducerAuthDisabled ProducerAuthMode = iota
	ProducerAuthRequired
)

// String renders the mode for diagnostic output.
func (m ProducerAuthMode) String() string {
	switch m {
	case ProducerAuthDisabled:
		return "Disabled"
	case ProducerAuthRequired:
		return "Required"
	default:
		return fmt.Sprintf("ProducerAuthMode(%d)", int(m))
	}
}

// ProducerAuthorizer is the interface VerifyHeadersWithOptions calls to
// decide whether a header's producer is authorized for its slot.
//
// Authorize takes (height, timestampUnix, pubkey). The timestamp is
// non-optional: a height-only check would admit a timestamp-mutation
// attack (go-zenon's GetMomentumProducer resolves the expected
// producer via timestamp, not height).
type ProducerAuthorizer interface {
	Authorize(height uint64, timestampUnix uint64, pubkey []byte) ProducerDecision
	Source() ProducerSource
}

// ProducerAuthOptions controls producer authorization for one call.
// A nil Authorizer with Required mode yields REFUSED for every header
// (Codex review v1 P2 lock-in: no silent downgrade).
type ProducerAuthOptions struct {
	Mode       ProducerAuthMode
	Authorizer ProducerAuthorizer
}

func (o ProducerAuthOptions) validate() error {
	switch o.Mode {
	case ProducerAuthDisabled:
		return nil
	case ProducerAuthRequired:
		if o.Authorizer == nil {
			return errors.New("producer authorization required but no authorizer configured")
		}
		return nil
	default:
		return fmt.Errorf("unsupported producer authorization mode %d", o.Mode)
	}
}

// VerifyOptions bundles per-call verifier knobs. Policy stays for
// resource and finality settings; producer-auth lives here so it can
// evolve independently without churning Policy callers.
type VerifyOptions struct {
	Policy       Policy
	ProducerAuth ProducerAuthOptions
}

// ProducerCoverage declares a contiguous height range the schedule
// attests producer values for. A height outside any Coverage entry is
// `unknown` (REFUSED), never extrapolated.
type ProducerCoverage struct {
	FromHeight    uint64 `json:"from_height"`
	ThroughHeight uint64 `json:"through_height"`
}

// ProducerEntry is one (height, timestamp, expected-producer-address)
// triple. Entries are sorted by Height and dense within each Coverage
// range — every covered height has its own entry.
//
// Timestamp is part of the entry because go-zenon's election resolves
// the expected producer by timestamp; binding only height would admit
// a timestamp-mutation attack (Codex review v2 P1).
type ProducerEntry struct {
	Height        uint64        `json:"height"`
	TimestampUnix uint64        `json:"timestamp_unix"`
	ProducingAddr chain.Address `json:"producing_addr"`
}

// ProducerSchedule is the operator-attested per-momentum schedule
// loaded via --schedule. The substantive content (ChainID + Coverage
// + Entries) hashes to ScheduleHash; tampering with any entry
// invalidates the recompute. Metadata is non-load-bearing audit
// trail and is excluded from the hash.
type ProducerSchedule struct {
	ChainID  uint64             `json:"chain_id"`
	Coverage []ProducerCoverage `json:"coverage"`
	Entries  []ProducerEntry    `json:"entries"`

	GeneratedAt   int64             `json:"generated_at"`
	SourcePeers   []string          `json:"source_peers"`
	SourceHeights map[string]uint64 `json:"source_heights"`

	ScheduleHash chain.Hash `json:"schedule_hash"`

	// idx maps height -> Entries index, populated by Validate so
	// LookupEntry runs in O(1). Not serialized.
	idx map[uint64]int `json:"-"`
}

// These limits accommodate the existing million-momentum sidecar design.
// They bound operator-supplied data, not the amount of authenticated history.
const (
	MaxProducerScheduleEntries   = 1_000_000
	MaxProducerScheduleFileBytes = 256 * 1024 * 1024
)

var ErrProducerScheduleTooLarge = errors.New("producer schedule exceeds resource limit")

func validateScheduleSize(coverage []ProducerCoverage, entries []ProducerEntry) error {
	if len(entries) > MaxProducerScheduleEntries || len(coverage) > MaxProducerScheduleEntries {
		return fmt.Errorf("%w: at most %d entries and coverage ranges", ErrProducerScheduleTooLarge, MaxProducerScheduleEntries)
	}
	return nil
}

// computeScheduleHash returns the SHA3-256 over the canonical
// big-endian encoding of substantive schedule content. Metadata
// (GeneratedAt, SourcePeers, SourceHeights) is intentionally
// excluded so two operators deriving the same range from the same
// peers produce identical hashes.
func computeScheduleHash(chainID uint64, coverage []ProducerCoverage, entries []ProducerEntry) chain.Hash {
	d := sha3.New256()
	var u8 [8]byte

	binary.BigEndian.PutUint64(u8[:], chainID)
	d.Write(u8[:])

	binary.BigEndian.PutUint64(u8[:], uint64(len(coverage)))
	d.Write(u8[:])
	for _, c := range coverage {
		binary.BigEndian.PutUint64(u8[:], c.FromHeight)
		d.Write(u8[:])
		binary.BigEndian.PutUint64(u8[:], c.ThroughHeight)
		d.Write(u8[:])
	}

	binary.BigEndian.PutUint64(u8[:], uint64(len(entries)))
	d.Write(u8[:])
	for _, e := range entries {
		binary.BigEndian.PutUint64(u8[:], e.Height)
		d.Write(u8[:])
		binary.BigEndian.PutUint64(u8[:], e.TimestampUnix)
		d.Write(u8[:])
		d.Write(e.ProducingAddr[:])
	}

	var out chain.Hash
	copy(out[:], d.Sum(nil))
	return out
}

// Validate enforces the structural invariants of a schedule and
// populates the internal lookup index. Run once at load time; the
// schedule is then read-only.
//
// Invariants checked:
//   - Coverage non-empty, sorted by FromHeight, non-overlapping, FromHeight ≤ ThroughHeight.
//   - Entries sorted by Height ascending.
//   - Every height in every Coverage range has exactly one Entry
//     (dense, no gaps, no duplicates).
//   - Recomputed ScheduleHash matches the stored value.
func (s *ProducerSchedule) Validate() error {
	// A failed revalidation must not leave a usable index from an earlier call.
	s.idx = nil
	if err := validateScheduleSize(s.Coverage, s.Entries); err != nil {
		return err
	}
	if len(s.Coverage) == 0 {
		return errors.New("producer schedule: empty coverage")
	}
	for i, c := range s.Coverage {
		if c.FromHeight > c.ThroughHeight {
			return fmt.Errorf("producer schedule: coverage[%d] from=%d > through=%d", i, c.FromHeight, c.ThroughHeight)
		}
		if i > 0 && c.FromHeight <= s.Coverage[i-1].ThroughHeight {
			return fmt.Errorf("producer schedule: coverage[%d] from=%d overlaps prior through=%d", i, c.FromHeight, s.Coverage[i-1].ThroughHeight)
		}
	}

	for i := 1; i < len(s.Entries); i++ {
		if s.Entries[i].Height <= s.Entries[i-1].Height {
			return fmt.Errorf("producer schedule: entries not strictly ascending at index %d (height=%d, prior=%d)",
				i, s.Entries[i].Height, s.Entries[i-1].Height)
		}
	}

	// Walk both sorted lists together. Work is bounded by the number of
	// entries, even when an interval claims the entire uint64 height space.
	ei := 0
	for ci, c := range s.Coverage {
		for h := c.FromHeight; ; h++ {
			if ei < len(s.Entries) && s.Entries[ei].Height < h {
				return fmt.Errorf("producer schedule: entry[%d] height %d falls outside declared coverage", ei, s.Entries[ei].Height)
			}
			if ei == len(s.Entries) || s.Entries[ei].Height != h {
				return fmt.Errorf("producer schedule: coverage[%d] height %d has no entry (dense-coverage requirement)", ci, h)
			}
			ei++
			if h == c.ThroughHeight {
				break // Never increment a terminal MaxUint64 height.
			}
		}
	}
	if ei != len(s.Entries) {
		return fmt.Errorf("producer schedule: entry[%d] height %d falls outside declared coverage", ei, s.Entries[ei].Height)
	}

	recomputed := computeScheduleHash(s.ChainID, s.Coverage, s.Entries)
	if recomputed != s.ScheduleHash {
		return fmt.Errorf("producer schedule: ScheduleHash mismatch (recomputed=%x stored=%x)", recomputed, s.ScheduleHash)
	}
	s.idx = make(map[uint64]int, len(s.Entries))
	for i, e := range s.Entries {
		s.idx[e.Height] = i
	}
	return nil
}

// LookupEntry returns the entry at the given height and whether the
// height is covered. Validate must have been called first.
func (s *ProducerSchedule) LookupEntry(height uint64) (ProducerEntry, bool) {
	if s.idx == nil {
		return ProducerEntry{}, false
	}
	i, ok := s.idx[height]
	if !ok {
		return ProducerEntry{}, false
	}
	return s.Entries[i], true
}

// LoadProducerSchedule reads, parses, and validates a schedule from
// one bounded JSON object with known fields only. On success the returned
// schedule has its lookup index populated and is ready for authorization.
func LoadProducerSchedule(path string) (*ProducerSchedule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read schedule: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat schedule: %w", err)
	}
	if info.Size() > MaxProducerScheduleFileBytes {
		return nil, fmt.Errorf("%w: file exceeds %d bytes", ErrProducerScheduleTooLarge, MaxProducerScheduleFileBytes)
	}
	// The bounded read also handles files growing after Stat and streams
	// whose reported size does not reflect how many bytes they can yield.
	return decodeProducerSchedule(f, MaxProducerScheduleFileBytes)
}

func decodeProducerSchedule(r io.Reader, maxBytes int64) (*ProducerSchedule, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read schedule: %w", err)
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%w: file exceeds %d bytes", ErrProducerScheduleTooLarge, maxBytes)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	var s ProducerSchedule
	if err := d.Decode(&s); err != nil {
		return nil, fmt.Errorf("decode schedule: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("decode schedule: trailing JSON")
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("validate schedule: %w", err)
	}
	return &s, nil
}

// Tiny JSON objects can expand into much larger structs. Stop array decoding
// at the count cap rather than allocating every row before Validate runs.
type boundedScheduleRows[T any] []T

func (rows *boundedScheduleRows[T]) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	first, err := d.Token()
	if err != nil {
		return err
	}
	if first == nil {
		*rows = nil
		return nil
	}
	if first != json.Delim('[') {
		return errors.New("producer schedule: expected an array")
	}
	decoded := make([]T, 0)
	for d.More() {
		if len(decoded) == MaxProducerScheduleEntries {
			return ErrProducerScheduleTooLarge
		}
		var row T
		if err := d.Decode(&row); err != nil {
			return err
		}
		decoded = append(decoded, row)
	}
	if _, err := d.Token(); err != nil {
		return err
	}
	*rows = decoded
	return nil
}

// NewProducerSchedule builds a schedule from raw components, computes
// the ScheduleHash, and validates the result. Intended for the
// derivation tool; production callers use LoadProducerSchedule.
func NewProducerSchedule(chainID uint64, coverage []ProducerCoverage, entries []ProducerEntry, peers []string, peerHeights map[string]uint64) (*ProducerSchedule, error) {
	if err := validateScheduleSize(coverage, entries); err != nil {
		return nil, err
	}
	s := &ProducerSchedule{
		ChainID:       chainID,
		Coverage:      append([]ProducerCoverage(nil), coverage...),
		Entries:       append([]ProducerEntry(nil), entries...),
		GeneratedAt:   time.Now().Unix(),
		SourcePeers:   append([]string(nil), peers...),
		SourceHeights: peerHeights,
		ScheduleHash:  computeScheduleHash(chainID, coverage, entries),
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// ScheduleAuthorizer implements ProducerAuthorizer over a validated
// ProducerSchedule.
type ScheduleAuthorizer struct {
	Schedule *ProducerSchedule
}

// NewScheduleAuthorizer wraps a validated schedule.
func NewScheduleAuthorizer(s *ProducerSchedule) *ScheduleAuthorizer {
	return &ScheduleAuthorizer{Schedule: s}
}

// Authorize implements ProducerAuthorizer.
//
// Decision order matters: Unknown before Unauthorized, so a caller
// distinguishes "I cannot judge" from "I judged and it failed".
func (a *ScheduleAuthorizer) Authorize(height uint64, timestampUnix uint64, pubkey []byte) ProducerDecision {
	entry, ok := a.Schedule.LookupEntry(height)
	if !ok {
		return ProducerSetUnknown
	}
	if entry.TimestampUnix != timestampUnix {
		return ProducerUnauthorized
	}
	if chain.PubKeyToAddress(pubkey) != entry.ProducingAddr {
		return ProducerUnauthorized
	}
	return ProducerAuthorized
}

// Source returns OperatorAttested for schedule-backed authorizers.
// A future ChainDerivedAuthorizer would return LocallyDerivedFromChain.
func (a *ScheduleAuthorizer) Source() ProducerSource { return ProducerSourceOperatorAttested }

// AuthorizeRetainedWindow re-runs producer authorization across
// every header in a persisted HeaderState. Closes the downgrade
// hole where a state file built without --schedule (or with a
// different schedule) is resumed under a new authorizer — the
// retained-window momenta backing commitment/segment verification
// never ran through producer auth, but the CLI would print the
// tier-2 caveat as if they had.
//
// Returns ACCEPT when all retained momentum versions are supported and:
//   - producer auth is Disabled, or
//   - every retained header authorizes cleanly under the configured
//     schedule.
//
// Returns REJECT/ReasonUnauthorizedProducer when any retained
// header fails authorization (FailedAt = window index), REFUSED/
// ReasonProducerSetUnknown when any retained header is outside the
// schedule's coverage or no authorizer is configured under Required
// mode. An unsupported retained momentum version returns REFUSED /
// ReasonUnsupportedHeaderVersion even when producer auth is Disabled.
//
// Cost: O(len(RetainedWindow)) authorizer calls. The retained
// window is bounded by persistence limits. Reauthorization includes headers
// that a smaller selected capacity will subsequently evict.
func AuthorizeRetainedWindow(state HeaderState, opts VerifyOptions) Result {
	if err := opts.Policy.ValidateRetention(); err != nil {
		return protocolFailure(err)
	}
	// Authorization also runs before resize on the full saved window. Its
	// original capacity need not equal the newly selected retention policy.
	if err := state.validateProtocolRules(opts.Policy); err != nil {
		return protocolFailure(err)
	}
	if err := opts.ProducerAuth.validate(); err != nil {
		return refuse(ReasonProducerSetUnknown, err.Error())
	}
	if opts.ProducerAuth.Mode == ProducerAuthDisabled {
		return withProtocolTrust(accept().WithNotProven(GuaranteeProducerAuthorization), state.ProtocolProfile)
	}
	for i, h := range state.RetainedWindow {
		switch decision := opts.ProducerAuth.Authorizer.Authorize(h.Height, h.TimestampUnix, h.PublicKey); decision {
		case ProducerAuthorized:
			// fall through
		case ProducerUnauthorized:
			return reject(ReasonUnauthorizedProducer, i,
				fmt.Sprintf("retained-window header at height=%d not authorized by configured schedule", h.Height))
		case ProducerSetUnknown:
			return refuse(ReasonProducerSetUnknown,
				fmt.Sprintf("retained-window header at height=%d not covered by configured schedule", h.Height))
		default:
			return refuse(ReasonProducerSetUnknown,
				fmt.Sprintf("unsupported producer authorization decision %d at retained height=%d", decision, h.Height))
		}
	}

	result := accept().WithProven(GuaranteeProducerAuthorization)
	if opts.ProducerAuth.Authorizer.Source() == ProducerSourceOperatorAttested {
		result = result.WithTrust(TrustExternalProducerSchedule)
	}
	return withProtocolTrust(result, state.ProtocolProfile)
}
