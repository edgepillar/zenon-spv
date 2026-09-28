package fetch

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestMultiFrontierZeroQuorumAllPeersUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	multi := NewMultiClient([]string{server.URL})
	multi.Quorum = 0
	header, err := multi.FetchFrontierAtAgreedHeight(context.Background(), 0)
	if header.HeaderHash != (chain.Hash{}) || !errors.Is(err, ErrNotEnoughPeers) {
		t.Fatalf("unavailable frontier returned evidence: height=%d err=%v", header.Height, err)
	}
}

// These adapters assert that failure never returns partial evidence.
func failedMultiQueries() map[string]func(*testing.T, *MultiClient) error {
	return map[string]func(*testing.T, *MultiClient) error{
		"headers": func(t *testing.T, m *MultiClient) error {
			h, err := m.FetchByHeight(context.Background(), 99, 1)
			if len(h) != 0 {
				t.Fatal("failed query returned headers")
			}
			return err
		},
		"detailed": func(t *testing.T, m *MultiClient) error {
			h, err := m.FetchByHeightDetailed(context.Background(), 99, 1)
			if len(h) != 0 {
				t.Fatal("failed query returned detailed headers")
			}
			return err
		},
		"frontier": func(t *testing.T, m *MultiClient) error {
			h, err := m.FetchFrontierAtAgreedHeight(context.Background(), 0)
			if h.Height != 0 || !h.HeaderHash.IsZero() {
				t.Fatal("failed query returned a frontier")
			}
			return err
		},
		"account blocks": func(t *testing.T, m *MultiClient) error {
			blocks, err := m.FetchAccountBlocksByHeight(context.Background(), "synthetic-address", 1, 1)
			if len(blocks) != 0 {
				t.Fatal("failed query returned account blocks")
			}
			return err
		},
	}
}

func TestMultiInvalidConfigurationMakesNoRequests(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	peer := NewClient(server.URL)
	for name, multi := range map[string]*MultiClient{
		"nil client":          nil,
		"empty peers":         {},
		"negative quorum":     {Peers: []*Client{peer}, Quorum: -1},
		"excessive quorum":    {Peers: []*Client{peer}, Quorum: 2},
		"nil peer":            {Peers: []*Client{peer, nil}, Quorum: 1},
		"missing HTTP client": {Peers: []*Client{peer, {URL: server.URL + "/private-peer-value"}}, Quorum: 1},
		"empty URL":           {Peers: []*Client{peer, NewClient(" \t")}, Quorum: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if err := multi.Validate(); !errors.Is(err, ErrInvalidPeerConfiguration) {
				t.Fatalf("invalid configuration validated: %v", err)
			}
			for name, query := range failedMultiQueries() {
				t.Run(name, func(t *testing.T) {
					err := query(t, multi)
					if !errors.Is(err, ErrInvalidPeerConfiguration) {
						t.Fatalf("want configuration error, got %v", err)
					}
					if strings.Contains(err.Error(), "private-peer-value") || strings.Contains(err.Error(), server.URL) {
						t.Fatal("configuration error echoed a peer URL")
					}
					if requests.Load() != 0 {
						t.Fatal("invalid configuration triggered RPC activity")
					}
				})
			}
		})
	}
}

func TestMultiZeroQuorumAllQueriesRefuseUnavailablePeers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	multi := NewMultiClient([]string{server.URL})
	multi.Quorum = 0
	for name, query := range failedMultiQueries() {
		t.Run(name, func(t *testing.T) {
			if err := query(t, multi); !errors.Is(err, ErrNotEnoughPeers) {
				t.Fatalf("unavailable unanimous quorum: %v", err)
			}
			if multi.Quorum != 0 {
				t.Fatal("query changed the caller's quorum setting")
			}
		})
	}
}

func TestMultiFrontierQuorumAppliesBeforeTargetQuery(t *testing.T) {
	var targetRequests atomic.Int64
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid test request", http.StatusBadRequest)
			return
		}
		var result any = emptyContentMomentum(99)
		if req.Method == "ledger.getMomentumsByHeight" {
			targetRequests.Add(1)
			result = map[string]any{"list": []any{emptyContentMomentum(99)}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
	defer good.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer dead.Close()
	for _, q := range []int{0, 2, 1} {
		targetRequests.Store(0)
		multi := NewMultiClient([]string{good.URL, dead.URL})
		multi.Quorum = q
		header, err := multi.FetchFrontierAtAgreedHeight(context.Background(), 0)
		if q == 1 {
			if err != nil || header.Height != 99 || targetRequests.Load() != 1 {
				t.Fatalf("explicit one-peer quorum did not complete target agreement: %v", err)
			}
		} else if !errors.Is(err, ErrNotEnoughPeers) || header.Height != 0 || targetRequests.Load() != 0 {
			t.Fatalf("quorum %d started target lookup without enough frontiers: %v", q, err)
		}
		if multi.Quorum != q {
			t.Fatal("frontier query changed the caller's quorum")
		}
	}
}

func TestMultiZeroQuorumAgreementAndDisagreement(t *testing.T) {
	a, b := twoServers(t, nil)
	multi := NewMultiClient([]string{a, b})
	multi.Quorum = 0
	if err := multi.Validate(); err != nil || multi.Quorum != 0 {
		t.Fatalf("explicit unanimous setting is invalid or was mutated: %v", err)
	}
	if h, err := multi.FetchByHeight(context.Background(), 99, 1); err != nil || len(h) != 1 {
		t.Fatalf("unanimous header agreement: %v", err)
	}
	if h, err := multi.FetchByHeightDetailed(context.Background(), 99, 1); err != nil || len(h) != 1 {
		t.Fatalf("unanimous detailed agreement: %v", err)
	}
	if h, err := multi.FetchFrontierAtAgreedHeight(context.Background(), 0); err != nil || h.Height != 99 {
		t.Fatalf("unanimous frontier agreement: %v", err)
	}
	a, b = twoServers(t, func(m map[string]any) { m["timestamp"] = uint64(1700001234) })
	for _, q := range []int{0, 1} {
		multi := NewMultiClient([]string{a, b})
		multi.Quorum = q
		if h, err := multi.FetchFrontierAtAgreedHeight(context.Background(), 0); !errors.Is(err, ErrPeerDisagreement) || h.Height != 0 {
			t.Fatalf("quorum %d masked disagreement: %v", q, err)
		}
	}
}
