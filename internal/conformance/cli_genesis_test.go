package conformance_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestCompiledGenesisRequiresExpectedHashAndEveryPeer(t *testing.T) {
	binary := buildQueryCLIs(t, "verify-mainnet-genesis")["verify-mainnet-genesis"]
	// This unsigned synthetic genesis exercises command pinning, not the
	// independently sourced content or provenance of the embedded mainnet root.
	h := chain.Header{Version: 1, ChainIdentifier: 1, Height: 1, TimestampUnix: 1700000000,
		DataHash: sha3.Sum256(nil), ContentHash: sha3.Sum256(nil), ChangesHash: chain.Hash{2}}
	h.HeaderHash = h.ComputeHash()
	var failLast atomic.Bool
	var calls atomic.Int64
	urls := make([]string, 3)
	for i := range urls {
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if i == 2 && failLast.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			var req struct {
				ID     json.RawMessage
				Method string
				Params []uint64
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Method != "ledger.getMomentumsByHeight" ||
				len(req.Params) != 2 || req.Params[0] != 1 || req.Params[1] != 1 {
				t.Error("unexpected genesis request")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			wire := map[string]any{"version": h.Version, "chainIdentifier": h.ChainIdentifier, "height": h.Height,
				"hash": h.HeaderHash, "previousHash": h.PreviousHash, "timestamp": h.TimestampUnix, "changesHash": h.ChangesHash,
				"data": "", "content": []any{}, "publicKey": "", "signature": ""}
			if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"list": []any{wire}}}); err != nil {
				t.Error(err)
			}
		}))
		t.Cleanup(peer.Close)
		urls[i] = strings.Replace(peer.URL, "://", "://PRIVATE_RPC_USER:PRIVATE_RPC_PASSWORD@", 1) + "/PRIVATE_RPC_PATH?key=PRIVATE_RPC_TOKEN"
	}
	base := []string{"--peers", strings.Join(urls, ",")}
	result := runQueryCLI(t, binary, base...)
	if result.code != 1 || len(result.stdout) != 0 || calls.Load() != 3 ||
		string(result.stderr) != "verify-mainnet-genesis: genesis observation differs from the expected hash\n" {
		t.Fatal("default invocation learned a new trust root from peer agreement")
	}
	pinned := append(append([]string{}, base...), "--expected", fmt.Sprintf("%x", h.HeaderHash))
	result = runQueryCLI(t, binary, pinned...)
	if result.code != 0 || len(result.stderr) != 0 || calls.Load() != 6 ||
		!bytes.Contains(result.stdout, []byte("3/3 configured peers match the explicit expected hash")) {
		t.Fatal("explicit pin failed or misreported its provenance")
	}
	failLast.Store(true)
	result = runQueryCLI(t, binary, pinned...)
	if result.code != 1 || len(result.stdout) != 0 || calls.Load() != 9 || !bytes.Contains(result.stderr, []byte("peer[3]")) {
		t.Fatal("unavailable peer was counted as agreeing")
	}
	result = runQueryCLI(t, binary, append(append([]string{}, base...), "--expected", "")...)
	if result.code != 1 || len(result.stdout) != 0 || calls.Load() != 9 {
		t.Fatal("empty pin disabled verification or reached RPC")
	}
}
