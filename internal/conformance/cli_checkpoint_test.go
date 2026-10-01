package conformance_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCompiledCheckpointRefusesNonMainnetCorpus(t *testing.T) {
	binary := buildQueryCLIs(t, "derive-checkpoints")["derive-checkpoints"]
	c, _, _ := transitionFixture(t)
	if c.Transition.Anchor.ChainID == 1 {
		t.Fatal("test requires a non-mainnet source-pinned corpus")
	}
	var calls atomic.Int64
	urls := make([]string, 3)
	for i := range urls {
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			var req struct {
				ID     json.RawMessage
				Method string
				Params []uint64
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Method != "ledger.getMomentumsByHeight" ||
				len(req.Params) != 2 || req.Params[0] != 2001 || req.Params[1] != 1 {
				t.Error("checkpoint collection continued after the wrong-chain observation")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			result := map[string]any{"list": []json.RawMessage{c.Transition.Vectors[0].Momentum}}
			if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}); err != nil {
				t.Error(err)
			}
		}))
		t.Cleanup(peer.Close)
		urls[i] = strings.Replace(peer.URL, "://", "://PRIVATE_RPC_USER:PRIVATE_RPC_PASSWORD@", 1) + "/PRIVATE_RPC_PATH?token=PRIVATE_RPC_TOKEN"
	}
	result := runQueryCLI(t, binary, "--peers", strings.Join(urls, ","), "--heights", "2001,2002")
	if result.code != 1 || len(result.stdout) != 0 || calls.Load() != 3 ||
		string(result.stderr) != "derive-checkpoints: height 2001: checkpoint observation is not mainnet chain_id=1\n" {
		t.Fatal("foreign-chain observations produced mainnet checkpoint output or unsafe diagnostics")
	}
}
