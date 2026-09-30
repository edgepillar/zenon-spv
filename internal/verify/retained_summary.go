package verify

import "github.com/0x3639/zenon-spv/internal/chain"

// RetainedSummary describes the effective window under the handle's captured
// policy. It does not authenticate file provenance, recover evicted ancestry,
// or establish a proof result. Pointer fields contain detached values.
type RetainedSummary struct {
	Count         int                 `json:"count"`
	Capacity      int                 `json:"capacity"`
	Oldest        *chain.HashHeight   `json:"oldest"`
	Tip           *chain.HashHeight   `json:"tip"`
	DepthEligible *RetainedDepthRange `json:"depth_eligible"`
}

// RetainedDepthRange includes retained heights with at least W headers after
// them. This is only a depth condition; it is not inclusion or finality.
type RetainedDepthRange struct {
	FromHeight    uint64 `json:"from_height"`
	ThroughHeight uint64 `json:"through_height"`
}

// RetainedSummary returns a constant-size diagnostic without copying headers,
// signatures, or the protocol profile. An initialized empty state has no bounds
// or depth-eligible range; a zero handle returns ErrUninitializedState.
func (s VerifiedState) RetainedSummary() (RetainedSummary, error) {
	if s.data == nil {
		return RetainedSummary{}, ErrUninitializedState
	}
	window := s.data.state.RetainedWindow
	summary := RetainedSummary{Count: len(window), Capacity: s.data.state.Capacity}
	if len(window) == 0 {
		return summary, nil
	}
	first, last := window[0], window[len(window)-1]
	summary.Oldest = &chain.HashHeight{Hash: first.HeaderHash, Height: first.Height}
	summary.Tip = &chain.HashHeight{Hash: last.HeaderHash, Height: last.Height}
	if last.Height-first.Height >= s.data.opts.Policy.W {
		summary.DepthEligible = &RetainedDepthRange{FromHeight: first.Height,
			ThroughHeight: last.Height - s.data.opts.Policy.W}
	}
	return summary, nil
}
