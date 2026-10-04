package fetch

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
)

// MaxSelectedMomentumHeights bounds explicit evidence selection and its RPC
// round trips. It is a collection limit, not a consensus or retention limit.
const MaxSelectedMomentumHeights = 1024

// ParseMomentumHeights accepts canonical decimal heights in strictly increasing
// order within (checkpoint, end]. The caller selects the window and every
// evidence location; RPC confirmation metadata is never a trust input.
func ParseMomentumHeights(value string, checkpoint, end uint64) ([]uint64, error) {
	if checkpoint == 0 || end <= checkpoint || value == "" || len(value) > 32<<10 ||
		strings.Count(value, ",") >= MaxSelectedMomentumHeights {
		return nil, errors.New("invalid momentum-height selection")
	}
	parts := strings.Split(value, ",")
	heights := make([]uint64, 0, len(parts))
	previous := checkpoint
	for _, part := range parts {
		h, err := strconv.ParseUint(part, 10, 64)
		if err != nil || strconv.FormatUint(h, 10) != part || h <= previous || h > end {
			return nil, errors.New("momentum heights must be increasing unique decimals inside the selected window")
		}
		heights = append(heights, h)
		previous = h
	}
	return heights, nil
}

func validateSelectedHeights(heights []uint64) error {
	// One extra row is permitted for the collector's unchanged checkpoint.
	if len(heights) == 0 || len(heights) > MaxSelectedMomentumHeights+1 {
		return errors.New("invalid selected momentum count")
	}
	var previous uint64
	for _, h := range heights {
		if h <= previous {
			return errors.New("selected momentum heights must be positive, unique and increasing")
		}
		previous = h
	}
	return nil
}

// FetchSelectedDetailed queries each explicit height with count=1. All rows
// share one response-byte and nested-evidence budget; failure discards the whole
// selection. This assembles candidates without authenticating their location.
func (c *Client) FetchSelectedDetailed(ctx context.Context, heights []uint64) ([]DetailedHeader, error) {
	if err := validateSelectedHeights(heights); err != nil {
		return nil, err
	}
	return c.fetchSelectedDetailed(ctx, heights, newRPCEvidenceDecoder(), newRPCResponseBudget())
}

func (c *Client) fetchSelectedDetailed(ctx context.Context, heights []uint64, evidence *rpcEvidenceDecoder, budget *rpcResponseBudget) ([]DetailedHeader, error) {
	var out []DetailedHeader
	for _, h := range heights {
		rows, err := c.fetchDetailedRange(ctx, h, 1, evidence, budget)
		if err != nil {
			return nil, err
		}
		out = append(out, rows[0])
	}
	return out, nil
}

// FetchSelectedDetailed reconciles each peer's complete selection. A quorum
// cannot be assembled from different peers' partial height responses. Budgets
// remain per peer, and agreement has the existing RPC-quorum trust boundary.
func (m *MultiClient) FetchSelectedDetailed(ctx context.Context, heights []uint64) ([]DetailedHeader, error) {
	q, err := m.requiredQuorum()
	if err != nil {
		return nil, err
	}
	if err := validateSelectedHeights(heights); err != nil {
		return nil, err
	}
	results := make([]peerDetailedResult, len(m.Peers))
	var wg sync.WaitGroup
	for i, p := range m.Peers {
		wg.Add(1)
		go func(i int, p *Client) {
			defer wg.Done()
			d, err := p.FetchSelectedDetailed(ctx, heights)
			results[i] = peerDetailedResult{label: PeerLabel(i), detailed: d, err: err}
		}(i, p)
	}
	wg.Wait()
	return reconcileDetailed(results, q)
}
