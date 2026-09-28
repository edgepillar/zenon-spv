package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestCommitmentExpansionRefusesAggregateOverflow(t *testing.T) {
	content := make([]chain.AccountHeader, 1001)
	details := []fetch.DetailedHeader{{Content: content}}
	got, err := buildCommitments(details, []chain.Address{{}})
	if err == nil || got != nil {
		t.Fatalf("returned %d commitments with %d aggregate members, exceeding %d", len(got), len(got)*len(content), verify.DefaultMaxTotalFlatEvidenceMembers)
	}
}

func TestCommitmentExpansionBounds(t *testing.T) {
	target, other := chain.Address{1}, chain.Address{2}
	content := func(n, matches int) []chain.AccountHeader {
		out := make([]chain.AccountHeader, n)
		for i := range out {
			out[i] = chain.AccountHeader{Address: other, Height: uint64(i + 1)}
			if i < matches {
				out[i].Address = target
			}
		}
		return out
	}
	for _, tc := range []struct {
		name    string
		details []fetch.DetailedHeader
		want    int
		refuse  bool
	}{
		{"empty", nil, 0, false},
		{"no matching targets", []fetch.DetailedHeader{{Content: content(100001, 0)}}, 0, false},
		{"per evidence boundary", []fetch.DetailedHeader{{Content: content(100000, 1)}}, 1, false},
		{"per evidence overflow", []fetch.DetailedHeader{{Content: content(100001, 1)}}, 0, true},
		{"aggregate boundary", []fetch.DetailedHeader{{Content: content(1000, 1000)}}, 1000, false},
		{"aggregate across momentums", []fetch.DetailedHeader{{Content: content(1000, 500)}, {Content: content(1001, 500)}}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildCommitments(tc.details, []chain.Address{target, target})
			if (err != nil) != tc.refuse || len(got) != tc.want || (tc.refuse && got != nil) {
				t.Fatalf("commitments=%d err=%v", len(got), err)
			}
		})
	}
	// Isolate the commitment count from the aggregate member count.
	details := make([]fetch.DetailedHeader, verify.DefaultMaxCommitments+1)
	for i := range details {
		details[i].Content = content(1, 1)
	}
	if got, err := buildCommitments(details[:verify.DefaultMaxCommitments], []chain.Address{target}); err != nil || len(got) != verify.DefaultMaxCommitments {
		t.Fatalf("count boundary failed: len=%d err=%v", len(got), err)
	}
	if got, err := buildCommitments(details, []chain.Address{target}); err == nil || got != nil {
		t.Fatal("count overflow returned partial evidence")
	}
	if got, err := buildCommitments(details, nil); err != nil || got != nil {
		t.Fatal("disabled commitments unexpectedly retained evidence")
	}
}

func TestCommitmentsRetainAllMembersAndOwnContent(t *testing.T) {
	a, b := chain.Address{1}, chain.Address{2}
	details := []fetch.DetailedHeader{{Header: chain.Header{Height: 12}, Content: []chain.AccountHeader{
		{Address: a, Height: 1}, {Address: b, Height: 2}, {Address: a, Height: 3},
	}}}
	got, err := buildCommitments(details, []chain.Address{a, a})
	if err != nil || len(got) != 2 {
		t.Fatalf("commitments=%d err=%v", len(got), err)
	}
	if got[0].Height != 12 || got[1].Target.Height != 3 || len(got[0].Flat.SortedHeaders) != 3 || got[0].Flat.SortedHeaders[1].Address != b {
		t.Fatal("bounded evidence dropped non-target content or changed target order")
	}
	details[0].Content[0].Height = 99
	if got[0].Flat.SortedHeaders[0].Height != 1 || got[0].Target.Height != 1 {
		t.Fatal("evidence retained caller-owned content")
	}
}

// Hash-consistent synthetic RPC data isolates assembly bounds. It is not a
// signature or consensus-validity fixture; those checks belong to the verifier.
func expansionPeer(t *testing.T, members int) string {
	t.Helper()
	content := make([]chain.AccountHeader, members)
	wireContent := make([]map[string]any, members)
	for i := range content {
		content[i].Height = uint64(i + 1)
		wireContent[i] = map[string]any{"address": "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f", "height": content[i].Height, "hash": chain.Hash{}}
	}
	var previous chain.Hash
	var list []map[string]any
	for height := uint64(1001); height <= 1002; height++ {
		members := content
		wireMembers := wireContent
		if height == 1001 {
			members, wireMembers = nil, nil
		}
		h := chain.Header{Version: 1, ChainIdentifier: 3, Height: height, PreviousHash: previous, DataHash: sha3.Sum256(nil), ContentHash: chain.MomentumContentHash(members)}
		h.HeaderHash = h.ComputeHash()
		list = append(list, map[string]any{
			"version": h.Version, "chainIdentifier": h.ChainIdentifier, "height": h.Height, "previousHash": h.PreviousHash,
			"hash": h.HeaderHash, "data": "", "content": wireMembers, "changesHash": h.ChangesHash, "publicKey": "", "signature": "",
		})
		previous = h.HeaderHash
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		if req.Method != "ledger.getMomentumsByHeight" {
			t.Errorf("unexpected request after commitment refusal: %s", req.Method)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"list": list}}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestBundleEvidenceRefusalPreservesOutputs(t *testing.T) {
	t.Setenv("ZENON_SPV_RPC", "")
	t.Setenv("ZENON_SPV_PEERS", "")
	for _, tc := range []struct {
		members int
		want    string
	}{
		{1001, "aggregate flat evidence"},
		// Exactly one million repeated flat members fit the count bound but
		// their compact JSON exceeds the independent 64 MiB wire limit.
		{1000, "bundle exceeds size cap"},
	} {
		t.Run(fmt.Sprint(tc.members), func(t *testing.T) {
			peer := expansionPeer(t, tc.members)
			for _, existing := range []bool{false, true} {
				dir := t.TempDir()
				paths := []string{filepath.Join(dir, "bundle.json"), filepath.Join(dir, "anchor.json")}
				before := []byte("previous output")
				if existing {
					for _, path := range paths {
						if err := os.WriteFile(path, before, 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}
				err := run([]string{"--rpc", peer, "--height", "1002", "--count", "1", "--commitments", "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f", "--out", paths[0], "--checkpoint", paths[1]})
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("unexpected refusal: %v", err)
				}
				for _, path := range paths {
					after, err := os.ReadFile(path)
					if existing && (err != nil || !bytes.Equal(before, after)) {
						t.Fatal("evidence refusal changed output")
					}
					if !existing && !os.IsNotExist(err) {
						t.Fatal("evidence refusal created output")
					}
				}
			}
		})
	}
}
