package conformance_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/syncer"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestWatchNodeTransitionPersistsV2Progress(t *testing.T) {
	c, headers, policy := transitionFixture(t)
	policy.W = 1
	result, initial := verify.VerifyHeaders(headers[:2], verify.NewHeaderState(c.Transition.Anchor, policy), policy)
	if result.Outcome != verify.OutcomeAccept {
		t.Fatal(result)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := verify.SaveHeaderState(path, initial); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params []uint64        `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			http.Error(w, "invalid request", 400)
			return
		}
		var response any
		switch req.Method {
		case "ledger.getFrontierMomentum":
			response = c.Transition.Vectors[5].Momentum
		case "ledger.getMomentumsByHeight":
			if !slices.Equal(req.Params, []uint64{2003, 3}) && !slices.Equal(req.Params, []uint64{2005, 1}) {
				t.Errorf("unexpected fetch range: %v", req.Params)
				http.Error(w, "unexpected range", 400)
				return
			}
			batch := make([]json.RawMessage, req.Params[1])
			for i := range batch {
				batch[i] = c.Transition.Vectors[req.Params[0]-2001+uint64(i)].Momentum
			}
			response = map[string]any{"list": batch}
		default:
			t.Errorf("unexpected method: %s", req.Method)
			http.Error(w, "unexpected method", 400)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": response}); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	saved := false
	loop := syncer.Loop{Multi: fetch.NewMultiClient([]string{srv.URL}), StatePath: path,
		Genesis: c.Transition.Anchor, Policy: policy, SafetyMargin: 1, BatchSize: 3,
		SaveState: func(path string, state verify.HeaderState) error {
			if err := verify.SaveHeaderState(path, state); err != nil {
				return err
			}
			saved = true
			cancel()
			return nil
		},
	}
	if err := loop.Run(ctx); err != nil || !saved {
		t.Fatalf("watch transition did not persist: %v", err)
	}
	state, err := verify.LoadOrInit(path, c.Transition.Anchor, policy)
	if err != nil {
		t.Fatal(err)
	}
	tip, ok := state.Tip()
	if !ok || tip.HeaderHash != headers[4].HeaderHash || tip.NextFusionPrice != headers[4].NextFusionPrice || tip.NextWorkPrice != headers[4].NextWorkPrice {
		t.Fatal("watch lost v2 price fields or persisted a different tip")
	}
}
