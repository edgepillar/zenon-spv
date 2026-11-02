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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func collectionWorkflowHash(t *testing.T, value string) chain.Hash {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		t.Fatal("fixture hash")
	}
	return chain.Hash(raw)
}

// These are existing recorded public signatures. The witness is deliberately
// incompatible with their root; this workflow cannot establish a positive
// BatchEntry query, selected-network activation or production acceptance.
func TestCompiledExperimentalBatchCandidateWorkflow(t *testing.T) {
	bins := buildQueryCLIs(t, "fetch-bundle", "zenon-spv")
	raw, err := os.ReadFile("../testdata/conformance/candidate-v3-node-rpc.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if len(raw) != 15475 || hex.EncodeToString(digest[:]) != "4ac2da237eead98f146d931a27679a7251a5a9ef5e109920b9f7fd1f3a383e57" {
		t.Fatal("recorded wire cohort changed")
	}
	var corpus struct {
		Rows []struct {
			Wire   string `json:"wire_json"`
			Signed bool   `json:"existing_signature_valid"`
		}
	}
	if json.Unmarshal(raw, &corpus) != nil || len(corpus.Rows) < 3 {
		t.Fatal("fixture schema")
	}
	var rows []json.RawMessage
	var headers []chain.CandidateV3Header
	var entries []verify.ProducerEntry
	for _, row := range corpus.Rows[:3] {
		if !row.Signed {
			t.Fatal("missing recorded signature")
		}
		value, err := fetch.DecodeCandidateV3Momentum([]byte(row.Wire))
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, json.RawMessage(row.Wire))
		headers = append(headers, value.Header)
		h := value.Header.Header
		entries = append(entries, verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
	}
	schedule, err := verify.NewProducerSchedule(100, []verify.ProducerCoverage{{FromHeight: 12, ThroughHeight: 14}}, entries, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := verify.ExperimentalV3Profile{Version: 1, Genesis: verify.GenesisTrustRoot{ChainID: 100, Height: 1, HeaderHash: collectionWorkflowHash(t, "0385d849ee33b94c8783288c148e3ae741c2ecec98b08b3f59d6bcc219168fe5")}, Anchor: verify.GenesisTrustRoot{ChainID: 100, Height: 11, HeaderHash: headers[0].Header.PreviousHash}, FirstV3Height: 12, ValidThrough: 14, NodeRevision: verify.ExperimentalV3NodeRevision, Source: "PRIVATE_HEADER_SOURCE recorded isolated fixture"}
	policy := verify.ExperimentalV3Policy{W: 1, RetainHeaders: 2, MaxBatchHeaders: 3}
	headerContext, err := verify.ExperimentalV3ContextFor(profile, policy, schedule)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := verify.NewExperimentalV3State(profile, policy, schedule, headerContext.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	queryProfile := verify.ExperimentalBatchEntryProfile{Version: 1, Settlement: verify.ExperimentalBatchEntrySettlementAddress(), DomainID: 1, RuntimeIdentity: chain.Hash{0x42, 0xab}, MaxProofBytes: proof.CandidateSMTMaxProofBytes, MaxSiblings: 256, Limits: verify.ExperimentalBatchEntryLimits{MaxValueBytes: 4096, MaxExecutorPillarBytes: 256, MaxAssetFlowSummaryBytes: 1024, MaxProofDataBytes: 1024, MaxDynamicBytes: 2048, StringRule: proof.CandidateBatchEntryUTF8String}, Source: "PRIVATE_QUERY_SOURCE not a live runtime selection"}
	queryContext, err := verify.ExperimentalBatchEntryContextFor(empty, queryProfile)
	if err != nil {
		t.Fatal(err)
	}
	if headerContext.Fingerprint != collectionWorkflowHash(t, "1f6961594b3e8950a1dad80f0a1e26b491e743e0a8f527e91802698b5084bdd2") || queryContext.Fingerprint != collectionWorkflowHash(t, "7f1d56a0cc151b8b499cc6cddc614d7e5b95e0d7645681fdc4b1283d0af46391") {
		t.Fatal("independently fixed contexts changed")
	}
	request := verify.ExperimentalBatchEntryRequest{Context: queryContext.Fingerprint, Height: 13, HeaderHash: headers[1].Header.HeaderHash, TipHeight: 14, TipHash: headers[2].Header.HeaderHash, BatchID: 1}
	path := proof.CandidateSettlementBatchEntryPath(queryProfile.Settlement, 1, 1)
	incompatible := make([]byte, 99)
	copy(incompatible[1:33], path[:])
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
			t.Error("unexpected RPC envelope")
			w.WriteHeader(400)
			return
		}
		var result any
		switch call.Method {
		case "ledger.getMomentumsByHeight":
			var p []uint64
			encoded, _ := json.Marshal(call.Params)
			if json.Unmarshal(encoded, &p) != nil || len(p) != 2 || p[0] != 12 || p[1] != 3 {
				t.Error("range selection changed")
			}
			result = map[string]any{"list": rows, "count": 3}
		case "ledger.getProof":
			var h uint64
			var key []byte
			want, _ := hex.DecodeString("0301b3b6e5adcb4d0cad7fcef33598c6318c6318c00402000000010000000000000001")
			if len(call.Params) != 2 || json.Unmarshal(call.Params[0], &h) != nil || json.Unmarshal(call.Params[1], &key) != nil || h != 13 || !bytes.Equal(key, want) {
				t.Error("height or full proof key changed")
			}
			result = map[string]any{"root": headers[1].StateRoot, "value": nil, "proof": incompatible}
		default:
			t.Error("unselected RPC method")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result}) != nil {
			t.Error("response write")
		}
	}))
	defer peer.Close()
	args := []string{"experimental-batch-entry", "--rpc", peer.URL, "--chain-id", "100", "--anchor-height", "11", "--anchor-hash", hex.EncodeToString(profile.Anchor.HeaderHash[:]), "--height", "13", "--header-hash", hex.EncodeToString(request.HeaderHash[:]), "--tip-height", "14", "--tip-hash", hex.EncodeToString(request.TipHash[:]), "--domain-id", "1", "--batch-id", "1"}
	collected := runQueryCLI(t, bins["fetch-bundle"], args...)
	if collected.code != 0 || len(collected.stderr) != 0 || calls.Load() != 2 {
		t.Fatal("candidate acquisition did not complete exactly its selected reads")
	}
	var bundle map[string]json.RawMessage
	if json.Unmarshal(collected.stdout, &bundle) != nil || len(bundle) != 3 {
		t.Fatal("candidate provider format changed")
	}
	dir := t.TempDir()
	bundlePath := writeCLIJSON(t, dir, "candidate.json", json.RawMessage(collected.stdout))
	configPath := writeCLIJSON(t, dir, "configuration.json", map[string]any{"version": 1, "header_profile": profile, "header_policy": policy, "producer_schedule": schedule, "query_profile": queryProfile})
	requestPath := writeCLIJSON(t, dir, "request.json", request)
	guards := []func(){protectCLIState(t, configPath), protectCLIState(t, requestPath), protectCLIState(t, bundlePath)}
	result := runQueryCLI(t, bins["zenon-spv"], "query-experimental-batch-entry", "--config", configPath, "--request", requestPath, "--expect-header-context", hex.EncodeToString(headerContext.Fingerprint[:]), "--expect-query-context", hex.EncodeToString(queryContext.Fingerprint[:]), bundlePath)
	var report struct {
		Status      string
		Result      json.RawMessage
		Headers     struct{ Outcome string }
		Error       struct{ Stage, Category string }
		Persistence string
		RPCRequests int  `json:"rpc_requests"`
		Production  bool `json:"production_state_value_guarantee"`
	}
	if result.code != 1 || len(result.stderr) != 0 || json.Unmarshal(result.stdout, &report) != nil || report.Status != "rejected" || report.Headers.Outcome != "ACCEPT" || report.Error.Stage != "query" || report.Error.Category != "invalid_witness" || string(report.Result) != "null" || report.Persistence != "read_only" || report.RPCRequests != 0 || report.Production {
		t.Fatal("candidate success or root hint bypassed the owned query")
	}
	if calls.Load() != 2 {
		t.Fatal("offline verifier performed another RPC read")
	}
	for _, guard := range guards {
		guard()
	}
	if bytes.Contains(result.stdout, []byte("PRIVATE_")) || strings.Contains(string(collected.stdout), peer.URL) {
		t.Fatal("private source or endpoint reached ordinary result")
	}
}
