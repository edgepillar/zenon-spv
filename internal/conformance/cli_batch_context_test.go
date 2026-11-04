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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
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
	var failedProof, proofReads, headerReads atomic.Int32
	var selectedStart, selectedCount atomic.Uint64
	selectedStart.Store(87)
	selectedCount.Store(4)
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
			headerReads.Add(1)
			var start, count uint64
			if len(call.Params) != 2 || json.Unmarshal(call.Params[0], &start) != nil || json.Unmarshal(call.Params[1], &count) != nil ||
				start != selectedStart.Load() || count != selectedCount.Load() {
				t.Error("selected header range changed")
				http.Error(w, "wrong range", 400)
				return
			}
			result = map[string]any{"list": unit.Momentums[start-87 : start-87+count], "count": count}
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
	type contextReport struct {
		Status      string
		ExitCode    int `json:"exit_code"`
		Result      *verify.ExperimentalBatchContextResult
		RPCRequests int `json:"rpc_requests"`
		Persistence string
		Production  bool `json:"production_state_value_guarantee"`
		StateInput  *struct {
			SHA256          string `json:"sha256"`
			Bytes           uint64 `json:"bytes"`
			ProviderHeaders uint32 `json:"provider_headers"`
			Trust           string `json:"trust"`
		} `json:"state_input"`
	}
	query := func(t *testing.T, arguments []string, want int) contextReport {
		t.Helper()
		actual := runQueryCLI(t, binaries["zenon-spv"], arguments...)
		var report contextReport
		if actual.code != want || json.Unmarshal(actual.stdout, &report) != nil || report.ExitCode != want ||
			report.RPCRequests != 0 || report.Persistence != "read_only" || report.Production || len(actual.stderr) != 0 {
			t.Fatal("compiled query envelope", actual.code, string(actual.stdout), string(actual.stderr))
		}
		if want != 0 {
			if report.Result != nil {
				t.Fatal("partial consumer row")
			}
			return report
		}
		if report.Result == nil || report.Status != "matched" || report.Result.Entry.FinalizeAtHeight != 87 ||
			report.Result.DomainConfig.WithdrawalDelay != 30 || hex.EncodeToString(report.Result.Root[:]) != unit.Expected.Root {
			t.Fatal("real command did not return the selected typed unit row")
		}
		return report
	}
	t.Run("typed_consumer", func(t *testing.T) { query(t, args, 0) })
	var checkpointConfig struct {
		Profile  verify.ExperimentalV3Profile `json:"header_profile"`
		Policy   verify.ExperimentalV3Policy  `json:"header_policy"`
		Schedule *verify.ProducerSchedule     `json:"producer_schedule"`
	}
	var headerPin chain.Hash
	if json.Unmarshal(unit.Config, &checkpointConfig) != nil || headerPin.UnmarshalText([]byte(unit.Expected.Header)) != nil {
		t.Fatal("checkpoint configuration")
	}
	headers := make([]chain.CandidateV3Header, 0, 4)
	for _, raw := range unit.Momentums {
		h, err := fetch.DecodeCandidateV3Momentum(raw)
		if err != nil {
			t.Fatal(err)
		}
		headers = append(headers, h.Header)
	}
	checkpoint := func(t *testing.T, count int, name string) (string, []byte) {
		t.Helper()
		state, err := verify.NewExperimentalV3State(checkpointConfig.Profile, checkpointConfig.Policy, checkpointConfig.Schedule, headerPin)
		if err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			outcome, next := state.Extend(headers[:count])
			if outcome.Outcome != verify.OutcomeAccept {
				t.Fatal(outcome)
			}
			state = next
		}
		path := filepath.Join(dir, name+".json")
		if err := state.Save(path); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return path, raw
	}
	checkpointArgs := func(path string, raw []byte, provider string) []string {
		pin := sha256.Sum256(raw)
		return append(append([]string(nil), args[:len(args)-1]...), "--trusted-state", path, "--expect-state-sha256", hex.EncodeToString(pin[:]), provider)
	}
	fullPath, fullCheckpoint := checkpoint(t, 4, "full-checkpoint")
	proofCollect := append(append([]string(nil), collect...), "--after-height", "90", "--after-hash", hex.EncodeToString(unit.Request.TipHash[:]))
	headerReads.Store(0)
	proofReads.Store(0)
	proofCapture := runQueryCLI(t, binaries["fetch-bundle"], proofCollect...)
	if proofCapture.code != 0 || len(proofCapture.stderr) != 0 || headerReads.Load() != 0 || proofReads.Load() != 3 || len(proofCapture.stdout) >= len(acquired.stdout) {
		t.Fatal("shipped collector did not omit the already retained header prefix")
	}
	proofOnly := filepath.Join(dir, "proof-only.json")
	if err := os.WriteFile(proofOnly, proofCapture.stdout, 0600); err != nil {
		t.Fatal(err)
	}
	t.Run("trusted_checkpoint_only", func(t *testing.T) {
		before, err := os.Stat(fullPath)
		if err != nil {
			t.Fatal(err)
		}
		r := query(t, checkpointArgs(fullPath, fullCheckpoint, proofOnly), 0)
		if r.StateInput == nil || r.StateInput.ProviderHeaders != 0 || r.StateInput.Bytes != uint64(len(fullCheckpoint)) || r.StateInput.Trust != "trusted_local_provenance_required" {
			t.Fatal("compiled checkpoint query omitted selected source")
		}
		trusted := false
		for _, value := range r.Result.HeaderTrust {
			trusted = trusted || value == verify.TrustPersistedState
		}
		after, err := os.Stat(fullPath)
		raw, readErr := os.ReadFile(fullPath)
		if !trusted || err != nil || readErr != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || !bytes.Equal(raw, fullCheckpoint) {
			t.Fatal("compiled read-only checkpoint changed provenance or bytes", err, readErr)
		}
	})
	t.Run("trusted_checkpoint_successors", func(t *testing.T) {
		defer func() { selectedStart.Store(87); selectedCount.Store(4); proofReads.Store(0) }()
		selectedStart.Store(89)
		selectedCount.Store(2)
		proofReads.Store(0)
		headerReads.Store(0)
		path, raw := checkpoint(t, 2, "prefix-checkpoint")
		// Keep the original anchor; the continuation is a separate transport
		// selector, not a replacement trust root or checkpoint authority.
		tailArgs := append(append([]string(nil), collect...), "--after-height", "88", "--after-hash", hex.EncodeToString(headers[1].Header.HeaderHash[:]))
		tail := runQueryCLI(t, binaries["fetch-bundle"], tailArgs...)
		if tail.code != 0 || proofReads.Load() != 3 || headerReads.Load() != 1 || len(tail.stderr) != 0 || len(tail.stdout) >= len(acquired.stdout) {
			t.Fatal("reduced candidate header range did not complete")
		}
		provider := filepath.Join(dir, "successors.json")
		if err := os.WriteFile(provider, tail.stdout, 0600); err != nil {
			t.Fatal(err)
		}
		r := query(t, checkpointArgs(path, raw, provider), 0)
		if r.StateInput == nil || r.StateInput.ProviderHeaders != 2 {
			t.Fatal("compiled successor query replayed the original anchor range")
		}
	})
	for _, name := range []string{"height_only", "hash_only", "tip_mismatch", "legacy_refused"} {
		t.Run("collector_resume_"+name, func(t *testing.T) {
			headerReads.Store(0)
			proofReads.Store(0)
			bad := append([]string(nil), collect...)
			switch name {
			case "height_only":
				bad = append(bad, "--after-height", "90")
			case "hash_only":
				bad = append(bad, "--after-hash", hex.EncodeToString(unit.Request.TipHash[:]))
			case "tip_mismatch":
				bad = append(bad, "--after-height", "90", "--after-hash", strings.Repeat("1", 64))
			case "legacy_refused":
				bad = append([]string(nil), proofCollect...)
				bad[0] = "experimental-batch-entry"
			}
			value := runQueryCLI(t, binaries["fetch-bundle"], bad...)
			if value.code != 64 || len(value.stdout) != 0 || headerReads.Load() != 0 || proofReads.Load() != 0 {
				t.Fatal("invalid continuation reached the provider")
			}
		})
	}
	t.Run("proof_only_requires_checkpoint", func(t *testing.T) {
		bad := append([]string(nil), args...)
		bad[len(bad)-1] = proofOnly
		query(t, bad, 2)
	})
	for _, name := range []string{"digest", "context", "tamper", "empty", "old_range", "pruned"} {
		t.Run("trusted_checkpoint_"+name, func(t *testing.T) {
			path, raw := checkpoint(t, 4, "control-"+name)
			selected := checkpointArgs(path, raw, proofOnly)
			want := 70
			switch name {
			case "digest":
				selected[len(selected)-2], want = strings.Repeat("1", 64), 1
			case "context", "tamper":
				bad := bytes.ReplaceAll(raw, []byte(unit.Expected.Root), []byte(strings.Repeat("1", 64)))
				if name == "context" {
					var value map[string]any
					if json.Unmarshal(raw, &value) != nil {
						t.Fatal("checkpoint context control")
					}
					value["context"] = strings.Repeat("1", 64)
					bad = mustBatchContextJSON(t, value)
				}
				if err := os.WriteFile(path, bad, 0600); err != nil {
					t.Fatal(err)
				}
				selected = checkpointArgs(path, bad, proofOnly)
			case "empty":
				path, raw = checkpoint(t, 0, "control-empty")
				selected = checkpointArgs(path, raw, proofOnly)
			case "old_range":
				selected, want = checkpointArgs(path, raw, bundlePath), 1
			case "pruned":
				request := unit.Request
				request.Height, request.HeaderHash = 88, headers[1].Header.HeaderHash
				selected[4] = writeCLIJSON(t, dir, "pruned-request.json", request)
				want = 2
			}
			query(t, selected, want)
		})
	}
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
		t.Run("resumed_collector_unavailable_"+strconv.Itoa(int(i)), func(t *testing.T) {
			proofReads.Store(0)
			headerReads.Store(0)
			failedProof.Store(i)
			value := runQueryCLI(t, binaries["fetch-bundle"], proofCollect...)
			failedProof.Store(0)
			if value.code != 1 || len(value.stdout) != 0 || headerReads.Load() != 0 || proofReads.Load() != i {
				t.Fatal("late resumed collection failure emitted partial bundle or fetched headers")
			}
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
		"checkpoint_provider_headers": []uint32{0, 2}, "checkpoint_file_unchanged": true, "checkpoint_signature_checks_retained": true,
		"collector_continuation_preserves_original_anchor": true, "resumed_late_collection_failures": 3, "proof_only_header_requests": 0,
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
