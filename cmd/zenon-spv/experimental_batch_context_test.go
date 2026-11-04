// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type batchContextCLIInputs struct {
	config, bundle                      map[string]any
	request                             verify.ExperimentalBatchContextRequest
	absent                              []byte
	headerPin, queryPin                 string
	configPath, requestPath, bundlePath string
}

func newBatchContextCLIInputs(t *testing.T) batchContextCLIInputs {
	t.Helper()
	raw, err := os.ReadFile("../../internal/testdata/conformance/batch-context-unit.json")
	sum := sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(sum[:]) != "e4bfbdb7bff55f9719782c7e609240b2ba9aeefd0d0f42b7ee1948286e890366" {
		t.Fatal("unit workflow fixture changed", err)
	}
	var fixture struct {
		Config    map[string]any
		Request   verify.ExperimentalBatchContextRequest
		Momentums []json.RawMessage
		Expected  map[string]string
	}
	// Expected also carries preimage lengths, so select its two pins separately.
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil || json.Unmarshal(doc["config"], &fixture.Config) != nil ||
		json.Unmarshal(doc["request"], &fixture.Request) != nil || json.Unmarshal(doc["momentums"], &fixture.Momentums) != nil {
		t.Fatal("unit workflow decode")
	}
	var expected struct {
		Header string `json:"header_context"`
		Query  string `json:"context"`
	}
	if json.Unmarshal(doc["expected"], &expected) != nil {
		t.Fatal("fixture pins")
	}
	raw, err = os.ReadFile("../../internal/testdata/conformance/batch-context-node-witness.json")
	sum = sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(sum[:]) != "773cda402e08709ffd73adfea355f73269b1470b7336c5a027ddd5b331ab9d96" {
		t.Fatal("original proof fixture changed", err)
	}
	var trace struct {
		Root string `json:"root_hex"`
		Rows []struct {
			Name  string
			Value string `json:"value_hex"`
			Proof string `json:"proof_hex"`
		}
	}
	if json.Unmarshal(raw, &trace) != nil || len(trace.Rows) != 4 {
		t.Fatal("proof fixture decode")
	}
	witnesses := map[string]any{}
	for _, row := range trace.Rows[:3] {
		value, err := hex.DecodeString(row.Value)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := hex.DecodeString(row.Proof)
		if err != nil {
			t.Fatal(err)
		}
		witnesses[row.Name] = map[string]any{"root": trace.Root, "value": value, "proof": encoded}
	}
	absent, err := hex.DecodeString(trace.Rows[3].Proof)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := batchContextCLIInputs{config: fixture.Config, request: fixture.Request,
		absent:    absent,
		bundle:    map[string]any{"version": 1, "momentums": fixture.Momentums, "witnesses": witnesses},
		headerPin: expected.Header, queryPin: expected.Query, configPath: filepath.Join(dir, "config.json"), requestPath: filepath.Join(dir, "request.json"), bundlePath: filepath.Join(dir, "bundle.json")}
	f.write(t)
	return f
}

func (f batchContextCLIInputs) write(t *testing.T) {
	t.Helper()
	for path, value := range map[string]any{f.configPath: f.config, f.requestPath: f.request, f.bundlePath: f.bundle} {
		if err := os.WriteFile(path, experimentalCLIJSON(t, value), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func (f batchContextCLIInputs) args() []string {
	return []string{"--config", f.configPath, "--request", f.requestPath, "--expect-header-context", f.headerPin, "--expect-query-context", f.queryPin, f.bundlePath}
}

func batchContextCLIReport(t *testing.T, command string, args []string, want int) experimentalContextCLIReport {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runExperimentalBatchContext(command, args, &stdout, &stderr)
	var report experimentalContextCLIReport
	if code != want || json.Unmarshal(stdout.Bytes(), &report) != nil || report.ExitCode != code || stderr.Len() != 0 ||
		report.Persistence != "read_only" || report.RPCRequests != 0 || report.ProductionStateValueGuarantee {
		t.Fatal("three-witness command scope", code, stdout.String(), stderr.String())
	}
	if code != 0 && report.Result != nil {
		t.Fatal("partial consumer result on failure")
	}
	if strings.Contains(stdout.String(), "PRIVATE") || strings.Contains(stderr.String(), "PRIVATE") {
		t.Fatal("private input exposed")
	}
	return report
}

func batchContextGateway(r verify.ExperimentalBatchContextResult) map[string]any {
	e := r.Entry
	return map[string]any{"domainId": r.Context.Entry.DomainID, "batchId": r.Request.BatchID,
		"protocolVersion": e.ProtocolVersion, "firstInputSeq": e.FirstInputSeq, "lastInputSeq": e.LastInputSeq,
		"preStateRoot": e.PreStateRoot, "postStateRoot": e.PostStateRoot, "inputRoot": e.InputRoot, "receiptRoot": e.ReceiptRoot,
		"eventRoot": e.EventRoot, "outboxRoot": e.OutboxRoot, "daHash": e.DaHash, "daMode": e.DaMode, "executorPillar": e.ExecutorPillar,
		"submittedAtHeight": e.SubmittedAtHeight, "finalizeAtHeight": e.FinalizeAtHeight,
		"assetFlowSummary": e.AssetFlowSummary, "proofData": e.ProofData, "state": e.State, "isFinalized": true}
}

func TestExperimentalBatchContextCLIConsumerAndGateway(t *testing.T) {
	f := newBatchContextCLIInputs(t)
	inspect := batchContextCLIReport(t, experimentalContextConfigCommand, []string{"--config", f.configPath}, 0)
	if inspect.Status != "inspected" || inspect.Headers != nil || inspect.Result != nil || inspect.QueryContext == nil {
		t.Fatal("diagnostics supplied authority")
	}
	report := batchContextCLIReport(t, experimentalContextQueryCommand, f.args(), 0)
	if report.Status != "matched" || report.Headers == nil || report.Headers.Outcome != "ACCEPT" || report.Result == nil ||
		report.Result.Entry.FinalizeAtHeight != 87 || report.Result.DomainConfig.WithdrawalDelay != 30 {
		t.Fatal("consumer result missing")
	}
	for _, mismatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "stored_match", true: "newer_frontier_differs"}[mismatch], func(t *testing.T) {
			gateway := batchContextGateway(*report.Result)
			if mismatch {
				gateway["finalizeAtHeight"] = uint64(999)
			}
			f.bundle["gateway"] = gateway
			f.write(t)
			args := append(f.args()[:len(f.args())-1], "--compare-gateway", f.bundlePath)
			compared := batchContextCLIReport(t, experimentalContextQueryCommand, args, 0)
			if compared.Result == nil || compared.Gateway == nil || compared.Gateway.StoredFieldsMatch == mismatch ||
				compared.Gateway.FrontierIdentityAuthenticated || !compared.Gateway.FrontierIsFinalizedHint ||
				compared.Result.Entry.FinalizeAtHeight != 87 {
				t.Fatal("frontier replaced proven history")
			}
		})
	}
}

func TestExperimentalBatchContextCLIFailuresAndBounds(t *testing.T) {
	for _, name := range []string{"request-context", "header-pin", "query-pin", "wrong-tip", "wrong-header", "old-profile", "old-bundle", "witnesses-null", "config-oversize", "proven-absence"} {
		t.Run(name, func(t *testing.T) {
			f := newBatchContextCLIInputs(t)
			args := f.args()
			want := 70
			switch name {
			case "request-context":
				f.request.Context[0] ^= 1
			case "header-pin":
				args[5] = strings.Repeat("1", 64)
			case "query-pin":
				args[7] = strings.Repeat("1", 64)
			case "wrong-tip":
				f.request.TipHash[0] ^= 1
				want = 1
			case "wrong-header":
				f.request.HeaderHash[0] ^= 1
				want = 1
			case "old-profile":
				f.config["query_profile"] = f.config["query_profile"].(map[string]any)["entry"]
			case "old-bundle":
				f.bundle["witness"] = f.bundle["witnesses"]
				delete(f.bundle, "witnesses")
			case "witnesses-null":
				f.bundle["witnesses"] = nil
			case "proven-absence":
				f.request.BatchID = 1
				row := f.bundle["witnesses"].(map[string]any)["batch_entry"].(map[string]any)
				row["proof"], row["value"] = f.absent, nil
				want = 2
			}
			f.write(t)
			if name == "config-oversize" {
				if err := os.WriteFile(f.configPath, bytes.Repeat([]byte(" "), maxExperimentalConfigBytes+1), 0600); err != nil {
					t.Fatal(err)
				}
			}
			report := batchContextCLIReport(t, experimentalContextQueryCommand, args, want)
			if name == "proven-absence" && (report.Error == nil || report.Error.Category != "required_row_absent") {
				t.Fatal("required-row absence became application BatchEntry absence")
			}
		})
	}
	for _, row := range []string{"batch_entry", "domain_record", "domain_config"} {
		for _, change := range []string{"unavailable", "missing", "root", "hint-value", "oversize-wire"} {
			t.Run(row+"/"+change, func(t *testing.T) {
				f := newBatchContextCLIInputs(t)
				rows := f.bundle["witnesses"].(map[string]any)
				want := 1
				switch change {
				case "unavailable":
					rows[row] = nil
					want = 2
				case "missing":
					delete(rows, row)
					want = 70
				case "root":
					rows[row].(map[string]any)["root"] = strings.Repeat("1", 64)
				case "hint-value":
					rows[row].(map[string]any)["value"] = []byte{1}
				case "oversize-wire":
					rows[row].(map[string]any)["proof"] = strings.Repeat("x", int(32<<10))
					want = 70
				}
				f.write(t)
				batchContextCLIReport(t, experimentalContextQueryCommand, f.args(), want)
			})
		}
	}
}

func TestExperimentalBatchContextCLIStrictSchemaAndArguments(t *testing.T) {
	f := newBatchContextCLIInputs(t)
	config, err := decodeExperimentalContextCLIConfig(experimentalCLIJSON(t, f.config))
	if err != nil {
		t.Fatal(err)
	}
	for kind, value := range map[string]any{"config": f.config, "bundle": f.bundle, "witnesses": f.bundle["witnesses"]} {
		raw := experimentalCLIJSON(t, value)
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			t.Fatal("fixture object")
		}
		for field := range fields {
			for _, change := range []string{"null", "missing", "duplicate", "alias"} {
				t.Run(kind+"/"+field+"/"+change, func(t *testing.T) {
					var changed map[string]json.RawMessage
					if json.Unmarshal(raw, &changed) != nil {
						t.Fatal("fixture object")
					}
					switch change {
					case "null":
						changed[field] = json.RawMessage("null")
					case "missing":
						delete(changed, field)
					case "alias":
						changed[strings.ToUpper(field)] = changed[field]
						delete(changed, field)
					}
					bad := experimentalCLIJSON(t, changed)
					if change == "duplicate" {
						bad = append(bad[:len(bad)-1], ',')
						bad = append(bad, experimentalCLIJSON(t, field)...)
						bad = append(bad, ':')
						bad = append(bad, changed[field]...)
						bad = append(bad, '}')
					}
					if kind == "config" {
						if _, err := decodeExperimentalContextCLIConfig(bad); err == nil {
							t.Fatal("ambiguous config")
						}
						return
					}
					if kind == "witnesses" {
						doc := map[string]any{"version": 1, "momentums": f.bundle["momentums"], "witnesses": json.RawMessage(bad)}
						bad = experimentalCLIJSON(t, doc)
					}
					bundle, err := decodeExperimentalContextCLIBundle(bad, config.HeaderPolicy.MaxBatchHeaders, false)
					if err == nil || bundle.Headers != nil || bundle.Gateway != nil {
						t.Fatal("ambiguous provider document")
					}
				})
			}
		}
	}
	missing := filepath.Join(t.TempDir(), "PRIVATE_MISSING")
	for _, args := range [][]string{nil, {"--config", missing}, {"--config", missing, "--PRIVATE=PRIVATE"},
		{"--config", missing, "--request", missing, "--expect-header-context", f.headerPin, "--expect-query-context", f.queryPin, "--expect-query-context", f.queryPin, missing},
		{"--config", missing, "--request", missing, "--expect-header-context", strings.Repeat("0", 64), "--expect-query-context", f.queryPin, missing}} {
		batchContextCLIReport(t, experimentalContextQueryCommand, args, 64)
	}
	// Output refusal is observable and never represented as success.
	report := experimentalContextCLIReport{Command: experimentalContextQueryCommand, Result: &verify.ExperimentalBatchContextResult{Entry: proof.CandidateBatchEntry{ExecutorPillar: string([]byte{255})}}}
	var stdout, stderr bytes.Buffer
	if code := finishExperimentalBatchContext(report, 0, &stdout, &stderr); code != 70 || !bytes.Contains(stdout.Bytes(), []byte("encoding")) || bytes.Contains(stdout.Bytes(), []byte("batch_membership")) {
		t.Fatal("lossy output accepted")
	}
}
