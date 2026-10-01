package verify

import (
	"fmt"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// HeaderState carries the verifier's retained policy window and the
// trust anchors needed to extend it.
//
// Storage capacity K is independent of the required subsequent-header depth W.
// Zero Policy.RetainHeaders preserves legacy K=W+1. Explicit K permits
// delayed queries at multiple heights. The oldest header is evicted on Append
// when full. Neither capacity nor depth establishes consensus finality.
//
// This type is the unit of offline-resume state in later phases:
// the verifier serializes HeaderState to disk and resumes from its
// LastVerified tip on next startup.
type HeaderState struct {
	ProtocolProfile *ProtocolProfile

	Genesis        GenesisTrustRoot
	RetainedWindow []chain.Header
	Capacity       int
	// RetainHeaders records explicit K, or zero for legacy W+1 semantics.
	RetainHeaders int
}

// capacityForPolicy returns explicit K or legacy W+1; zero means invalid.
func capacityForPolicy(policy Policy) int {
	if policy.ValidateRetention() != nil {
		return 0 // Invalid low-level states cannot pass verification or saving.
	}
	if policy.RetainHeaders != 0 {
		return policy.RetainHeaders
	}
	return int(policy.W) + 1
}

// NewHeaderState builds an empty state anchored at g, sized for
// explicit K or legacy W+1 headers of retention.
func NewHeaderState(g GenesisTrustRoot, policy Policy) HeaderState {
	cap := capacityForPolicy(policy)
	return HeaderState{
		ProtocolProfile: cloneProtocolProfile(policy.ProtocolProfile),
		Genesis:         g,
		RetainedWindow:  make([]chain.Header, 0, cap),
		Capacity:        cap,
		RetainHeaders:   policy.RetainHeaders,
	}
}

// Empty reports whether the state has no retained headers (i.e., the
// next append anchors against Genesis).
func (s HeaderState) Empty() bool { return len(s.RetainedWindow) == 0 }

// ValidateHeaderVersions checks the entire retained window before it
// supplies an anchor, depth evidence, or persisted state. This is a
// layout, activation-policy, and basic-price check, not a substitute for
// hash/signature verification or trusted-state provenance.
func (s HeaderState) ValidateHeaderVersions() error {
	if err := validateProfileAnchor(s.ProtocolProfile, s.Genesis); err != nil {
		return err
	}
	for i, h := range s.RetainedWindow {
		if err := validateProtocolHeader(h, s.ProtocolProfile); err != nil {
			return fmt.Errorf("retained header[%d] height=%d: %w", i, h.Height, err)
		}
	}
	return nil
}

// Tip returns the most recently appended header. ok is false when the
// state is empty (caller should anchor against Genesis instead).
func (s HeaderState) Tip() (chain.Header, bool) {
	if s.Empty() {
		return chain.Header{}, false
	}
	return s.RetainedWindow[len(s.RetainedWindow)-1], true
}

// Append adds h to the retained window, evicting the oldest entry if
// the window is at capacity.
func (s *HeaderState) Append(h chain.Header) {
	if len(s.RetainedWindow) < s.Capacity {
		s.RetainedWindow = append(s.RetainedWindow, h)
		return
	}
	copy(s.RetainedWindow, s.RetainedWindow[1:])
	s.RetainedWindow[len(s.RetainedWindow)-1] = h
}

// HeaderAtHeight returns the retained header at the given height in
// O(1) via contiguous-window offset arithmetic. The retained window
// is built by Append in ascending-height order with FIFO eviction
// (see Append), so a contiguous height range is the invariant; the
// height-equality check at the computed offset is a defensive guard
// against a malformed persisted state (e.g., a hand-edited state
// file with a height gap) — returns false rather than a
// silently-wrong header.
//
// Replaces the prior linear scan in VerifyCommitment.
func (s HeaderState) HeaderAtHeight(h uint64) (chain.Header, bool) {
	if len(s.RetainedWindow) == 0 {
		return chain.Header{}, false
	}
	first := s.RetainedWindow[0].Height
	if h < first {
		return chain.Header{}, false
	}
	offset := h - first
	if offset >= uint64(len(s.RetainedWindow)) {
		return chain.Header{}, false
	}
	hdr := s.RetainedWindow[offset]
	if hdr.Height != h {
		// Window is not contiguous — bail rather than return a
		// header whose height disagrees with the caller's query.
		return chain.Header{}, false
	}
	return hdr, true
}

// Cover reports whether every height in heights is present in the
// retained window. Used by callers that need to bind referenced
// commitments to authenticated headers (spec §4.4 — used in later
// phases).
func (s HeaderState) Cover(heights []uint64) bool {
	if len(heights) == 0 {
		return true
	}
	have := make(map[uint64]struct{}, len(s.RetainedWindow))
	for _, h := range s.RetainedWindow {
		have[h.Height] = struct{}{}
	}
	for _, want := range heights {
		if _, ok := have[want]; !ok {
			return false
		}
	}
	return true
}
