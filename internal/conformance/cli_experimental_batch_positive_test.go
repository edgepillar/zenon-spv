// SPDX-License-Identifier: MIT

package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Reuse the existing workflow's two fresh executables. All settings below are
// explicit synthetic fixture selections, not independently selected live trust.
func runRecordedPositiveBatchWorkflow(t *testing.T, bins map[string]string) {
	raw, err := os.ReadFile("../testdata/conformance/batch-entry-node-header-witness.json")
	digest := sha256.Sum256(raw)
	if err != nil || len(raw) != 13807 || hex.EncodeToString(digest[:]) != "cf784dae5b502d79de832d73e5da91055762249e2252811195fc41960a662d97" {
		t.Fatal("recorded positive node cohort changed", err)
	}
	var fixture struct {
		Trace struct {
			Height      uint64
			DomainID    uint32          `json:"domain_id"`
			LedgerKey   string          `json:"ledger_key"`
			AbsentBatch uint64          `json:"absent_batch_id"`
			Absent      json.RawMessage `json:"absent_witness"`
			Bundle      struct {
				Version   uint32
				Momentums []json.RawMessage
				Witness   json.RawMessage
				Gateway   json.RawMessage
			}
		}
		Selection struct {
			Config           json.RawMessage
			Request          verify.ExperimentalBatchEntryRequest
			HeaderContext    chain.Hash `json:"header_context"`
			QueryContext     chain.Hash `json:"query_context"`
			QueryFingerprint chain.Hash `json:"query_fingerprint"`
		} `json:"test_selection"`
	}
	if json.Unmarshal(raw, &fixture) != nil || len(fixture.Trace.Bundle.Momentums) != 3 {
		t.Fatal("recorded fixture schema")
	}
	f := &fixture
	var config struct {
		Version       uint32
		HeaderProfile verify.ExperimentalV3Profile         `json:"header_profile"`
		HeaderPolicy  verify.ExperimentalV3Policy          `json:"header_policy"`
		Schedule      *verify.ProducerSchedule             `json:"producer_schedule"`
		QueryProfile  verify.ExperimentalBatchEntryProfile `json:"query_profile"`
	}
	if json.Unmarshal(f.Selection.Config, &config) != nil {
		t.Fatal("explicit fixture configuration")
	}
	hc, err := verify.ExperimentalV3ContextFor(config.HeaderProfile, config.HeaderPolicy, config.Schedule)
	if err != nil || hc.Fingerprint != f.Selection.HeaderContext {
		t.Fatal("independent header-context bytes differ", err)
	}
	empty, err := verify.NewExperimentalV3State(config.HeaderProfile, config.HeaderPolicy, config.Schedule, f.Selection.HeaderContext)
	if err != nil {
		t.Fatal(err)
	}
	qc, err := verify.ExperimentalBatchEntryContextFor(empty, config.QueryProfile)
	if err != nil || qc.Fingerprint != f.Selection.QueryContext {
		t.Fatal("independent typed-context bytes differ", err)
	}
	headers := make([]chain.CandidateV3Header, 0, 3)
	for _, raw := range f.Trace.Bundle.Momentums {
		m, err := fetch.DecodeCandidateV3Momentum(raw)
		if err != nil {
			t.Fatal("original RPC row failed native projection", err)
		}
		headers = append(headers, m.Header)
	}
	accepted, state := empty.Extend(headers)
	if accepted.Outcome != verify.OutcomeAccept {
		t.Fatal("recorded signatures or configured producer authorization failed", accepted)
	}
	for _, guarantee := range accepted.Proven {
		if guarantee == verify.GuaranteeStateValueInclusion || guarantee == verify.GuaranteeCanonicality || guarantee == verify.GuaranteeStateTransition {
			t.Fatal("fixture header promoted an unsupported guarantee")
		}
	}
	query, err := verify.NewExperimentalBatchEntryQuery(state, config.QueryProfile, f.Selection.QueryContext)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := fetch.DecodeCandidateStateWitness(f.Trace.Bundle.Witness)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := fetch.DecodeCandidateSettlementBatch(f.Trace.Bundle.Gateway)
	if err != nil {
		t.Fatal(err)
	}
	result, err := query.QueryWithGateway(f.Selection.Request, witness, gateway)
	if err != nil || result.Scope != "EXPERIMENTAL_CONFIGURED_HEADER_MEMBERSHIP" || result.QueryFingerprint != f.Selection.QueryFingerprint ||
		result.Root != headers[1].StateRoot || result.LedgerKey != f.Trace.LedgerKey || !bytes.Equal(result.Value, witness.Value) ||
		result.Entry.ProtocolVersion != 1 || result.Entry.ExecutorPillar != "TEST-pillar-1" ||
		result.Gateway == nil || !result.Gateway.StoredFieldsMatch || result.Gateway.FrontierIdentityAuthenticated {
		t.Fatal("matching original-node proof did not produce the configured typed result", err)
	}
	t.Run("owned-query-and-resume", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "trusted-fixture-state.json")
		if state.Save(path) != nil {
			t.Fatal("owned fixture state could not be saved")
		}
		resumed, err := verify.LoadTrustedExperimentalV3State(path, config.HeaderProfile, config.HeaderPolicy, config.Schedule, f.Selection.HeaderContext)
		if err != nil {
			t.Fatal(err)
		}
		q, err := verify.NewExperimentalBatchEntryQuery(resumed, config.QueryProfile, f.Selection.QueryContext)
		if err != nil {
			t.Fatal(err)
		}
		got, err := q.QueryWithGateway(f.Selection.Request, witness, gateway)
		if err != nil || got.QueryFingerprint != result.QueryFingerprint || got.Root != result.Root || !bytes.Equal(got.Value, result.Value) {
			t.Fatal("saved context changed the matching query", err)
		}
		// Result mutations must change neither provider data nor a later query.
		original := append([]byte(nil), result.Value...)
		got.Value[0] ^= 1
		got.Entry.AssetFlowSummary[0] ^= 1
		got.Context.Fingerprint[0] ^= 1
		again, err := q.QueryWithGateway(f.Selection.Request, witness, gateway)
		if err != nil || !bytes.Equal(again.Value, original) || again.QueryFingerprint != result.QueryFingerprint {
			t.Fatal("detached result changed the owned query", err)
		}
	})
	t.Run("owned-typed-absence", func(t *testing.T) {
		request := f.Selection.Request
		request.BatchID = f.Trace.AbsentBatch
		absent, err := fetch.DecodeCandidateStateWitness(f.Trace.Absent)
		if err != nil {
			t.Fatal(err)
		}
		got, err := query.QueryWitness(request, absent)
		if !errors.Is(err, verify.ErrExperimentalBatchEntryAbsent) || !reflect.DeepEqual(got, verify.ExperimentalBatchEntryResult{}) {
			t.Fatal("real absence became a zero typed row", err)
		}
	})

	var calls atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var call struct {
			JSONRPC string
			ID      int
			Method  string
			Params  []json.RawMessage
		}
		if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&call) != nil || call.JSONRPC != "2.0" || call.ID != 1 {
			t.Error("unexpected fixture RPC request")
			w.WriteHeader(400)
			return
		}
		var response any
		switch call.Method {
		case "ledger.getMomentumsByHeight":
			var height, count uint64
			if len(call.Params) != 2 || json.Unmarshal(call.Params[0], &height) != nil || json.Unmarshal(call.Params[1], &count) != nil ||
				height != config.HeaderProfile.Anchor.Height+1 || count != 3 {
				t.Error("local header selection changed")
			}
			response = map[string]any{"list": f.Trace.Bundle.Momentums, "count": 3}
		case "ledger.getProof":
			var height uint64
			var key []byte
			if len(call.Params) != 2 || json.Unmarshal(call.Params[0], &height) != nil || json.Unmarshal(call.Params[1], &key) != nil ||
				height != f.Selection.Request.Height || hex.EncodeToString(key) != f.Trace.LedgerKey {
				t.Error("local full key or height changed")
			}
			response = f.Trace.Bundle.Witness
		case "embedded.settlement.getBatch":
			var domain uint32
			var batch uint64
			if len(call.Params) != 2 || json.Unmarshal(call.Params[0], &domain) != nil || json.Unmarshal(call.Params[1], &batch) != nil || domain != 1 || batch != 0 {
				t.Error("local gateway identity changed")
			}
			response = f.Trace.Bundle.Gateway
		default:
			t.Error("unselected fixture RPC method")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": response}) != nil {
			t.Error("fixture response write failed")
		}
	}))
	defer peer.Close()
	selected := f.Selection.Request
	args := []string{"experimental-batch-entry", "--rpc", peer.URL, "--chain-id", "100",
		"--anchor-height", strconv.FormatUint(config.HeaderProfile.Anchor.Height, 10), "--anchor-hash", hex.EncodeToString(config.HeaderProfile.Anchor.HeaderHash[:]),
		"--height", strconv.FormatUint(selected.Height, 10), "--header-hash", hex.EncodeToString(selected.HeaderHash[:]),
		"--tip-height", strconv.FormatUint(selected.TipHeight, 10), "--tip-hash", hex.EncodeToString(selected.TipHash[:]),
		"--domain-id", "1", "--batch-id", "0", "--compare-gateway"}
	collected := runQueryCLI(t, bins["fetch-bundle"], args...)
	if collected.code != 0 || len(collected.stderr) != 0 || calls.Load() != 3 {
		t.Fatal("positive collection did not complete its three selected reads")
	}
	dir := t.TempDir()
	configPath := writeCLIJSON(t, dir, "configuration.json", f.Selection.Config)
	requestPath := writeCLIJSON(t, dir, "request.json", selected)
	bundlePath := writeCLIJSON(t, dir, "provider.json", json.RawMessage(collected.stdout))
	guards := []func(){protectCLIState(t, configPath), protectCLIState(t, requestPath), protectCLIState(t, bundlePath)}
	queryArgs := []string{"query-experimental-batch-entry", "--config", configPath, "--request", requestPath,
		"--expect-header-context", hex.EncodeToString(f.Selection.HeaderContext[:]), "--expect-query-context", hex.EncodeToString(f.Selection.QueryContext[:]),
		"--compare-gateway", bundlePath}
	matched := runQueryCLI(t, bins["zenon-spv"], queryArgs...)
	var report struct {
		Status             string
		Scope              string
		ExitCode           int `json:"exit_code"`
		Result             *verify.ExperimentalBatchEntryResult
		Headers            struct{ Outcome string }
		Persistence        string
		RPCRequests        int  `json:"rpc_requests"`
		Production         bool `json:"production_state_value_guarantee"`
		ComparisonRequired bool `json:"gateway_comparison_required"`
	}
	if matched.code != 0 || len(matched.stderr) != 0 || json.Unmarshal(matched.stdout, &report) != nil || report.ExitCode != 0 ||
		report.Status != "matched" || report.Scope != result.Scope || report.Headers.Outcome != "ACCEPT" ||
		report.Persistence != "read_only" || report.RPCRequests != 0 || report.Production || !report.ComparisonRequired || report.Result == nil {
		t.Fatal("compiled consumer did not report its configured fixture membership")
	}
	want, _ := json.Marshal(result)
	got, err := json.Marshal(report.Result)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("compiled consumer and exported API differ", err)
	}
	for _, guard := range guards {
		guard()
	}
	t.Run("explicit-source-rule-original-node-bytes", func(t *testing.T) {
		profile := config.QueryProfile
		profile.Version, profile.SourceRule = 2, verify.ExperimentalBatchEntrySourceRule
		context, err := verify.ExperimentalBatchEntryContextFor(state, profile)
		if err != nil || hex.EncodeToString(context.Fingerprint[:]) != "203c1f61315054effea611d0a530819ee6a43be1a918165a9b24aec921261e62" {
			t.Fatal("independent version 2 context differs", err)
		}
		q, err := verify.NewExperimentalBatchEntryQuery(state, profile, context.Fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		request := selected
		request.Context = context.Fingerprint
		got, err := q.QueryWithGateway(request, witness, gateway)
		if err != nil || !reflect.DeepEqual(got.Entry, result.Entry) ||
			hex.EncodeToString(got.QueryFingerprint[:]) != "915a9a0836f57c4de9856da0317a8fe457cdfdf266529eab6770b6cbdf349b02" {
			t.Fatal("source rule changed the original proven row", err)
		}
		var configured map[string]json.RawMessage
		if json.Unmarshal(f.Selection.Config, &configured) != nil {
			t.Fatal("source-rule configuration")
		}
		configured["query_profile"], _ = json.Marshal(profile)
		dir := t.TempDir()
		c := writeCLIJSON(t, dir, "source-rule-config.json", configured)
		r := writeCLIJSON(t, dir, "source-rule-request.json", request)
		invocation := selectQueryCLIOption(queryArgs, "--config", c)
		invocation = selectQueryCLIOption(invocation, "--request", r)
		invocation = selectQueryCLIOption(invocation, "--expect-query-context", hex.EncodeToString(context.Fingerprint[:]))
		runCompiledSourceRuleReport(t, bins["zenon-spv"], invocation, true, result.Scope)
	})
	t.Run("compiled-identity-and-witness-refusals", func(t *testing.T) {
		for _, name := range []string{"provider-root", "value-hint", "proof-byte", "gateway-field", "local-batch", "header-identity", "tip-identity", "signature", "unavailable", "typed-absence"} {
			t.Run(name, func(t *testing.T) {
				var bundle struct {
					Version   uint32            `json:"version"`
					Momentums []json.RawMessage `json:"momentums"`
					Witness   json.RawMessage   `json:"witness"`
					Gateway   json.RawMessage   `json:"gateway"`
				}
				if json.Unmarshal(collected.stdout, &bundle) != nil {
					t.Fatal("collected fixture schema")
				}
				request, w, g := selected, witness, gateway
				code, stage, category := 1, "query", "invalid_witness"
				switch name {
				case "provider-root":
					w.Root[0] ^= 1
				case "value-hint":
					w.Value = append([]byte(nil), w.Value...)
					w.Value[0] ^= 1
				case "proof-byte":
					w.Proof = append([]byte(nil), w.Proof...)
					w.Proof[len(w.Proof)-1] ^= 1
				case "gateway-field":
					var dto map[string]json.RawMessage
					if json.Unmarshal(bundle.Gateway, &dto) != nil {
						t.Fatal("gateway schema")
					}
					dto["finalizeAtHeight"], _ = json.Marshal(g.Entry.FinalizeAtHeight + 1)
					bundle.Gateway, _ = json.Marshal(dto)
					category = "gateway_mismatch"
				case "local-batch":
					request.BatchID++
				case "header-identity":
					request.HeaderHash[0] ^= 1
					category = "query_identity_mismatch"
				case "tip-identity":
					request.TipHash[0] ^= 1
					category = "query_identity_mismatch"
				case "signature":
					var dto map[string]json.RawMessage
					if json.Unmarshal(bundle.Momentums[1], &dto) != nil {
						t.Fatal("momentum schema")
					}
					var signature []byte
					if json.Unmarshal(dto["signature"], &signature) != nil || len(signature) != 64 {
						t.Fatal("signature fixture")
					}
					signature[0] ^= 1
					dto["signature"], _ = json.Marshal(signature)
					bundle.Momentums[1], _ = json.Marshal(dto)
					stage, category = "headers", "not_accepted"
				case "unavailable":
					code, stage, category = 2, "witness", "unavailable"
				case "typed-absence":
					request.BatchID = f.Trace.AbsentBatch
					code, category = 2, "typed_value_absent"
				}
				bundle.Witness, _ = json.Marshal(map[string]any{"root": w.Root, "value": w.Value, "proof": w.Proof})
				if name == "unavailable" {
					bundle.Witness = json.RawMessage("null")
				}
				if name == "typed-absence" {
					bundle.Witness = f.Trace.Absent
				}
				d := t.TempDir()
				modifiedBundle := writeCLIJSON(t, d, "provider.json", bundle)
				modifiedRequest := writeCLIJSON(t, d, "request.json", request)
				invocation := selectQueryCLIOption(queryArgs, "--request", modifiedRequest)
				invocation[len(invocation)-1] = modifiedBundle
				observed := runQueryCLI(t, bins["zenon-spv"], invocation...)
				var refused struct {
					Result json.RawMessage
					Error  struct{ Stage, Category string }
				}
				decodeErr := json.Unmarshal(observed.stdout, &refused)
				if observed.code != code || len(observed.stderr) != 0 || decodeErr != nil ||
					string(refused.Result) != "null" || refused.Error.Stage != stage || refused.Error.Category != category {
					t.Fatalf("changed fixture outcome: code=%d stage=%s category=%s", observed.code, refused.Error.Stage, refused.Error.Category)
				}
			})
		}
	})
	if calls.Load() != 3 || bytes.Contains(matched.stdout, []byte(peer.URL)) {
		t.Fatal("offline queries made a new provider read or exposed its endpoint")
	}
}
