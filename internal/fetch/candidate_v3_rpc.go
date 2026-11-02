// SPDX-License-Identifier: MIT

package fetch

import (
	"context"
	"fmt"
)

// MaxCandidateV3RangeHeaders is a local experimental transport limit. Pages
// also share a cumulative response-byte budget; this is not consensus.
const MaxCandidateV3RangeHeaders uint64 = 4096

// MaxCandidateV3RangeBytes bounds the sum of all page response bodies,
// including wrappers and whitespace, independently of the native 64 MiB cap.
const MaxCandidateV3RangeBytes int64 = 8 * 1024 * 1024

// FetchCandidateV3ByHeight fetches a caller-selected range of untrusted v3
// candidates. It checks envelope/count/height/encoding/hash consistency only.
// Passing candidates to an explicitly configured owned verifier is a separate
// step. Production FetchByHeight/FetchFrontier continue to refuse version 3.
func (c *Client) FetchCandidateV3ByHeight(ctx context.Context, start, count uint64) ([]CandidateV3Momentum, error) {
	if err := validateHeightRange(start, count); err != nil {
		return nil, err
	}
	if count > MaxCandidateV3RangeHeaders {
		return nil, fmt.Errorf("%w: candidate v3 range exceeds its local header limit", ErrInvalidQuery)
	}
	return fetchHeightRange(ctx, c, "ledger.getMomentumsByHeight", start, count,
		func(height, size uint64) []any { return []any{height, size} },
		func(target *CandidateV3Momentum) any { return &candidateV3RPCDecoder{target: target} },
		func(row CandidateV3Momentum, index uint64) (CandidateV3Momentum, error) {
			if row.Header.Header.Height != start+index {
				return CandidateV3Momentum{}, ErrQueryMismatch
			}
			return row, nil
		}, &rpcResponseBudget{remaining: MaxCandidateV3RangeBytes})
}

type candidateV3RPCDecoder struct{ target *CandidateV3Momentum }

func (d *candidateV3RPCDecoder) UnmarshalJSON(raw []byte) error {
	value, err := DecodeCandidateV3Momentum(raw)
	if err != nil {
		return err
	}
	*d.target = value
	return nil
}
