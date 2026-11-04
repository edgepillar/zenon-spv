// SPDX-License-Identifier: MIT

package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/verify"
)

// Exercise both shipped main functions. The only endpoint is this test's
// loopback HTTP fixture; it is not a node, deployment or selected devnet.
// The pooled original-node proof bytes are bound to separate synthetic test
// headers, under a finite test profile/schedule and independently encoded pins.
func TestCompiledCLIExperimentalBatchContextWorkflow(t *testing.T) {
	unitRaw, err := os.ReadFile("../testdata/conformance/batch-context-unit.json")
	unitHash := sha256.Sum256(unitRaw)
	if err != nil || hex.EncodeToString(unitHash[:]) != "e4bfbdb7bff55f9719782c7e609240b2ba9aeefd0d0f42b7ee1948286e890366" {
		t.Fatal("unit fixture changed", err)
	}
	var unit struct {
		Config    json.RawMessage
		Request   verify.ExperimentalBatchContextRequest
		Momentums []json.RawMessage
		Expected  struct {
			Header  string `json:"header_context"`
			Context string `json:"context"`
			Root    string `json:"root"`
		}
	}
	if json.Unmarshal(unitRaw, &unit) != nil || len(unit.Momentums) != 4 {
		t.Fatal("unit fixture encoding")
	}
	traceRaw, err := os.ReadFile("../testdata/conformance/batch-context-node-witness.json")
	traceHash := sha256.Sum256(traceRaw)
	if err != nil || hex.EncodeToString(traceHash[:]) != "773cda402e08709ffd73adfea355f73269b1470b7336c5a027ddd5b331ab9d96" {
		t.Fatal("proof fixture changed", err)
	}
	var trace struct {
		Root string `json:"root_hex"`
		Rows []struct {
			Name  string
			Key   string `json:"ledger_key_hex"`
			Value string `json:"value_hex"`
			Proof string `json:"proof_hex"`
		}
	}
	if json.Unmarshal(traceRaw, &trace) != nil || len(trace.Rows) != 4 {
		t.Fatal("trace encoding")
	}
	witnesses := map[string]any{}
	byKey := map[string]any{}
	for _, row := range trace.Rows[:3] {
		value, err := hex.DecodeString(row.Value)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := hex.DecodeString(row.Proof)
		if err != nil {
			t.Fatal(err)
		}
		witness := map[string]any{"root": trace.Root, "value": value, "proof": proof}
		witnesses[row.Name], byKey[row.Key] = witness, witness
	}
	var failedProof, proofReads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call struct {
			Method string
			ID     json.RawMessage
			Params []json.RawMessage
		}
		if json.NewDecoder(r.Body).Decode(&call) != nil {
			t.Error("fixture RPC framing")
			http.Error(w, "bad fixture request", 400)
			return
		}
		var result any
		switch call.Method {
		case "ledger.getMomentumsByHeight":
			var start, count uint64
			if len(call.Params) != 2 || json.Unmarshal(call.Params[0], &start) != nil || json.Unmarshal(call.Params[1], &count) != nil ||
				start != 87 || count != 4 {
				t.Error("selected header range changed")
				http.Error(w, "wrong range", 400)
				return
			}
			result = map[string]any{"list": unit.Momentums, "count": 4}
		case "ledger.getProof":
			var height uint64
			var key []byte
			if len(call.Params) != 2 || json.Unmarshal(call.Params[0], &height) != nil || json.Unmarshal(call.Params[1], &key) != nil || height != 89 {
				t.Error("proof selector changed")
				http.Error(w, "wrong selection", 400)
				return
			}
			var ok bool
			result, ok = byKey[hex.EncodeToString(key)]
			if !ok {
				t.Error("provider was asked for a different key")
				http.Error(w, "wrong key", 400)
				return
			}
			n := proofReads.Add(1)
			if n == failedProof.Load() {
				result = nil
			}
		default:
			t.Error("unexpected RPC method")
			http.Error(w, "wrong method", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result}) != nil {
			t.Error("fixture response")
		}
	}))
	defer server.Close()
	binaries := buildQueryCLIs(t, "zenon-spv", "fetch-bundle")
	dir := t.TempDir()
	configPath := writeCLIJSON(t, dir, "config.json", unit.Config)
	requestPath := writeCLIJSON(t, dir, "request.json", unit.Request)
	anchor := struct {
		HeaderProfile struct {
			Anchor struct {
				Hash string `json:"header_hash"`
			}
		} `json:"header_profile"`
	}{}
	if json.Unmarshal(unit.Config, &anchor) != nil {
		t.Fatal("anchor decode")
	}
	collect := []string{"experimental-batch-context", "--rpc", server.URL, "--chain-id", "9001", "--anchor-height", "86", "--anchor-hash", anchor.HeaderProfile.Anchor.Hash,
		"--height", "89", "--header-hash", hex.EncodeToString(unit.Request.HeaderHash[:]), "--tip-height", "90", "--tip-hash", hex.EncodeToString(unit.Request.TipHash[:]), "--domain-id", "1", "--batch-id", "0"}
	acquired := runQueryCLI(t, binaries["fetch-bundle"], collect...)
	if acquired.code != 0 || len(acquired.stderr) != 0 || proofReads.Load() != 3 {
		t.Fatal("candidate acquisition incomplete", acquired.code, string(acquired.stderr))
	}
	bundlePath := filepath.Join(dir, "candidate.json")
	if err := os.WriteFile(bundlePath, acquired.stdout, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"query-experimental-batch-context", "--config", configPath, "--request", requestPath, "--expect-header-context", unit.Expected.Header, "--expect-query-context", unit.Expected.Context, bundlePath}
	query := func(t *testing.T, arguments []string, want int) {
		t.Helper()
		actual := runQueryCLI(t, binaries["zenon-spv"], arguments...)
		var report struct {
			Status      string
			ExitCode    int `json:"exit_code"`
			Result      *verify.ExperimentalBatchContextResult
			RPCRequests int `json:"rpc_requests"`
			Persistence string
			Production  bool `json:"production_state_value_guarantee"`
		}
		if actual.code != want || json.Unmarshal(actual.stdout, &report) != nil || report.ExitCode != want ||
			report.RPCRequests != 0 || report.Persistence != "read_only" || report.Production || len(actual.stderr) != 0 {
			t.Fatal("compiled query envelope", actual.code, string(actual.stdout), string(actual.stderr))
		}
		if want != 0 {
			if report.Result != nil {
				t.Fatal("partial consumer row")
			}
			return
		}
		if report.Result == nil || report.Status != "matched" || report.Result.Entry.FinalizeAtHeight != 87 ||
			report.Result.DomainConfig.WithdrawalDelay != 30 || hex.EncodeToString(report.Result.Root[:]) != unit.Expected.Root {
			t.Fatal("real command did not return the selected typed unit row")
		}
	}
	t.Run("typed_consumer", func(t *testing.T) { query(t, args, 0) })
	for i := int32(1); i <= 3; i++ {
		t.Run("collector_unavailable_"+strconv.Itoa(int(i)), func(t *testing.T) {
			proofReads.Store(0)
			failedProof.Store(i)
			value := runQueryCLI(t, binaries["fetch-bundle"], collect...)
			if value.code != 1 || len(value.stdout) != 0 {
				t.Fatal("late collection failure emitted partial bundle")
			}
			failedProof.Store(0)
		})
	}
	for _, name := range []string{"batch_entry", "domain_record", "domain_config"} {
		t.Run("missing_"+name, func(t *testing.T) {
			bad := map[string]any{}
			for key, value := range witnesses {
				bad[key] = value
			}
			bad[name] = nil
			provider := map[string]any{"version": 1, "momentums": unit.Momentums, "witnesses": bad}
			if err := os.WriteFile(bundlePath, mustBatchContextJSON(t, provider), 0600); err != nil {
				t.Fatal(err)
			}
			query(t, args, 2)
		})
	}
	if err := os.WriteFile(bundlePath, acquired.stdout, 0600); err != nil {
		t.Fatal(err)
	}
	t.Run("independent_context_required", func(t *testing.T) {
		bad := append([]string(nil), args...)
		bad[8] = unit.Expected.Header
		query(t, bad, 70)
	})
	t.Run("legacy_schema_refused", func(t *testing.T) {
		provider := map[string]any{"version": 1, "momentums": unit.Momentums, "witness": witnesses["batch_entry"]}
		if err := os.WriteFile(bundlePath, mustBatchContextJSON(t, provider), 0600); err != nil {
			t.Fatal(err)
		}
		query(t, args, 70)
	})
	if _, err := os.Stat(filepath.Join(dir, "trusted-state.json")); !os.IsNotExist(err) {
		t.Fatal("read-only query created state")
	}
	receipt := map[string]any{"format": "compiled-three-witness-consumer/v1", "scope": "SYNTHETIC_OFFLINE_CONSUMER", "typed_consumer": true,
		"three_complete_key_reads": true, "late_collection_failures": 3, "unavailable_contexts": 3, "provider_authority_imported": false,
		"production_state_value_accepted": false, "source_values_are_one_original_snapshot": false}
	t.Logf("three-witness-consumer %s", bytes.TrimSpace(mustBatchContextJSON(t, receipt)))
}

func mustBatchContextJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
