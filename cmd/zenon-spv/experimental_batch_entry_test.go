// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

const experimentalCLIHeaderPin = "1f6961594b3e8950a1dad80f0a1e26b491e743e0a8f527e91802698b5084bdd2"
const experimentalCLIQueryPin = "7f1d56a0cc151b8b499cc6cddc614d7e5b95e0d7645681fdc4b1283d0af46391"

func experimentalCLIJSON(t testing.TB, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func experimentalCLIHash(t testing.TB, value string) chain.Hash {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != chain.HashSize {
		t.Fatal("fixture hash")
	}
	return chain.Hash(raw)
}

type experimentalCLIFixture struct {
	config                              map[string]any
	request                             verify.ExperimentalBatchEntryRequest
	bundle                              map[string]any
	configPath, requestPath, bundlePath string
}

// Reuse the three original public signatures and their exact node projection.
// The selected context pins also have an independent Python byte oracle. This
// fixture does not produce a signature or a matching positive BatchEntry proof.
func newExperimentalCLIFixture(t testing.TB) experimentalCLIFixture {
	t.Helper()
	raw, err := os.ReadFile("../../internal/testdata/conformance/candidate-v3-node-rpc.json")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if len(raw) != 15475 || hex.EncodeToString(hash[:]) != "4ac2da237eead98f146d931a27679a7251a5a9ef5e109920b9f7fd1f3a383e57" {
		t.Fatal("pinned RPC fixture changed")
	}
	var corpus struct {
		Rows []struct {
			Name   string
			Wire   string `json:"wire_json"`
			Signed bool   `json:"existing_signature_valid"`
		}
	}
	if json.Unmarshal(raw, &corpus) != nil {
		t.Fatal("RPC fixture decode")
	}
	var rows []json.RawMessage
	var headers []chain.CandidateV3Header
	schedule := &verify.ProducerSchedule{ChainID: 100, Coverage: []verify.ProducerCoverage{{FromHeight: 12, ThroughHeight: 14}},
		ScheduleHash: experimentalCLIHash(t, "1101fc4fb75c9dbcfd26bc4ff7ec5b37b79522c130a18966d49bcc78ef6249ed")}
	for _, row := range corpus.Rows[:3] {
		if !row.Signed {
			t.Fatal("selected row has no recorded public signature")
		}
		value, err := fetch.DecodeCandidateV3Momentum([]byte(row.Wire))
		if err != nil {
			t.Fatal(err)
		}
		h := value.Header.Header
		rows = append(rows, json.RawMessage(row.Wire))
		headers = append(headers, value.Header)
		schedule.Entries = append(schedule.Entries, verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
	}
	profile := verify.ExperimentalV3Profile{Version: 1, Genesis: verify.GenesisTrustRoot{ChainID: 100, Height: 1, HeaderHash: experimentalCLIHash(t, "0385d849ee33b94c8783288c148e3ae741c2ecec98b08b3f59d6bcc219168fe5")},
		Anchor:        verify.GenesisTrustRoot{ChainID: 100, Height: 11, HeaderHash: experimentalCLIHash(t, "2b584eb276428450a3485d18df309d37352110d59cd670b25bc774837b5f5768")},
		FirstV3Height: 12, ValidThrough: 14, NodeRevision: verify.ExperimentalV3NodeRevision, Source: "PRIVATE_HEADER_SOURCE recorded synthetic configuration"}
	queryProfile := verify.ExperimentalBatchEntryProfile{Version: 1, Settlement: verify.ExperimentalBatchEntrySettlementAddress(), DomainID: 1, RuntimeIdentity: chain.Hash{0x42, 0xab}, MaxProofBytes: proof.CandidateSMTMaxProofBytes, MaxSiblings: 256,
		Limits: verify.ExperimentalBatchEntryLimits{MaxValueBytes: 4096, MaxExecutorPillarBytes: 256, MaxAssetFlowSummaryBytes: 1024, MaxProofDataBytes: 1024, MaxDynamicBytes: 2048, StringRule: proof.CandidateBatchEntryUTF8String}, Source: "PRIVATE_QUERY_SOURCE not a selected live runtime identity"}
	f := experimentalCLIFixture{config: map[string]any{"version": 1, "header_profile": profile, "header_policy": verify.ExperimentalV3Policy{W: 1, RetainHeaders: 2, MaxBatchHeaders: 3}, "producer_schedule": schedule, "query_profile": queryProfile},
		request: verify.ExperimentalBatchEntryRequest{Context: experimentalCLIHash(t, experimentalCLIQueryPin), Height: 13, HeaderHash: headers[1].Header.HeaderHash, TipHeight: 14, TipHash: headers[2].Header.HeaderHash, BatchID: 1}}
	path := proof.CandidateSettlementBatchEntryPath(queryProfile.Settlement, queryProfile.DomainID, f.request.BatchID)
	emptyProof := make([]byte, 99)
	copy(emptyProof[1:33], path[:])
	// Copying the signed header root into a provider hint cannot authorize this
	// proof: its actual mathematical root is zero, not that accepted root.
	f.bundle = map[string]any{"version": 1, "momentums": rows, "witness": map[string]any{"root": headers[1].StateRoot, "value": nil, "proof": emptyProof}}
	dir := t.TempDir()
	f.configPath, f.requestPath, f.bundlePath = filepath.Join(dir, "config.json"), filepath.Join(dir, "request.json"), filepath.Join(dir, "bundle.json")
	f.write(t)
	return f
}

func (f experimentalCLIFixture) write(t testing.TB) {
	t.Helper()
	for path, value := range map[string]any{f.configPath: f.config, f.requestPath: f.request, f.bundlePath: f.bundle} {
		if err := os.WriteFile(path, experimentalCLIJSON(t, value), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func (f experimentalCLIFixture) args() []string {
	return []string{"--config", f.configPath, "--request", f.requestPath, "--expect-header-context", experimentalCLIHeaderPin, "--expect-query-context", experimentalCLIQueryPin, f.bundlePath}
}

func experimentalCLIReportFor(t testing.TB, command string, args []string, want int) experimentalCLIReport {
	t.Helper()
	var out, diagnostics bytes.Buffer
	code := runExperimentalBatch(command, args, &out, &diagnostics)
	var report experimentalCLIReport
	if code != want || json.Unmarshal(out.Bytes(), &report) != nil || report.ExitCode != code || diagnostics.Len() != 0 {
		t.Fatalf("unexpected bounded command result: code=%d want=%d report=%s diagnostics=%s", code, want, out.Bytes(), diagnostics.Bytes())
	}
	if report.SchemaVersion != 1 || report.Command != command || report.Persistence != "read_only" || report.RPCRequests != 0 || report.ProductionStateValueGuarantee {
		t.Fatal("incorrect command scope")
	}
	for _, private := range []string{"PRIVATE_HEADER_SOURCE", "PRIVATE_QUERY_SOURCE", "PRIVATE_ARGUMENT", "PRIVATE_MISSING", fspathMarker} {
		if strings.Contains(out.String(), private) || strings.Contains(diagnostics.String(), private) {
			t.Fatal("private input reached ordinary diagnostics")
		}
	}
	if code != 0 && report.Result != nil {
		t.Fatal("failure exposed a partial typed row")
	}
	return report
}

const fspathMarker = "PRIVATE_FIXTURE_PATH"

func TestExperimentalBatchCLIConfigurationDiagnostics(t *testing.T) {
	f := newExperimentalCLIFixture(t)
	before, err := os.ReadFile(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.Remove(f.requestPath) != nil || os.Remove(f.bundlePath) != nil {
		t.Fatal("fixture")
	}
	r := experimentalCLIReportFor(t, experimentalConfigCommand, []string{"--config", f.configPath}, 0)
	if r.Status != "inspected" || r.Scope != "EXPERIMENTAL_CONFIGURATION_DIAGNOSTIC" || r.Result != nil || r.Headers != nil || r.Error != nil || r.HeaderContext == nil || r.QueryContext == nil {
		t.Fatal("diagnostic created a query result")
	}
	if r.HeaderContext.Fingerprint != experimentalCLIHash(t, experimentalCLIHeaderPin) || r.QueryContext.Fingerprint != experimentalCLIHash(t, experimentalCLIQueryPin) {
		t.Fatal("configuration differs from independent byte vectors")
	}
	after, err := os.ReadFile(f.configPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("inspection rewrote configuration")
	}
	files, err := os.ReadDir(filepath.Dir(f.configPath))
	if err != nil || len(files) != 1 || files[0].Name() != "config.json" {
		t.Fatal("inspection wrote state or locks")
	}
}

func TestExperimentalBatchCLIArgumentsBeforeInputs(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "PRIVATE_MISSING")
	base := []string{"--config", missing, "--request", missing, "--expect-header-context", experimentalCLIHeaderPin, "--expect-query-context", experimentalCLIQueryPin}
	cases := map[string][]string{
		"missing-config": {}, "missing-pins": {"--config", missing, "--request", missing, missing},
		"unknown":             append(append([]string{}, base...), "--PRIVATE_ARGUMENT=PRIVATE_ARGUMENT", missing),
		"repeated-config":     append(append([]string{}, base...), "--config", missing, missing),
		"repeated-request":    append(append([]string{}, base...), "-request="+missing, missing),
		"repeated-header-pin": append(append([]string{}, base...), "-expect-header-context="+experimentalCLIHeaderPin, missing),
		"repeated-query-pin":  append(append([]string{}, base...), "--expect-query-context=PRIVATE_ARGUMENT", missing),
		"repeated-comparison": append(append([]string{}, base...), "--compare-gateway", "--compare-gateway=false", missing),
		"extra-input":         append(append([]string{}, base...), missing, missing),
	}
	for _, name := range []string{"expect-header-context", "expect-query-context"} {
		for _, value := range []string{"", "PRIVATE_ARGUMENT", strings.Repeat("0", 64)} {
			args := []string{"--config", missing, "--request", missing, "--expect-header-context", experimentalCLIHeaderPin, "--expect-query-context", experimentalCLIQueryPin}
			for i := range args {
				if args[i] == "--"+name {
					args[i+1] = value
				}
			}
			cases[name+"/"+value] = append(args, missing)
		}
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			r := experimentalCLIReportFor(t, experimentalQueryCommand, args, 64)
			if r.Error == nil || r.Error.Stage != "arguments" || r.HeaderContext != nil || r.QueryContext != nil || r.Headers != nil {
				t.Fatal("bad arguments reached input processing")
			}
		})
	}
	for _, args := range [][]string{{"--config", missing, "--config", missing}, {"--config", missing, "--request", missing}, {"--config", missing, missing}} {
		if r := experimentalCLIReportFor(t, experimentalConfigCommand, args, 64); r.Error == nil || r.Error.Stage != "arguments" {
			t.Fatal("inspection accepted query controls")
		}
	}
}

func TestExperimentalBatchCLIIndependentPinsAndRequest(t *testing.T) {
	for _, name := range []string{"header-pin", "query-pin", "request-context", "request-overflow"} {
		t.Run(name, func(t *testing.T) {
			f := newExperimentalCLIFixture(t)
			args := f.args()
			stage := "configuration_pin"
			switch name {
			case "header-pin":
				args[5] = strings.Repeat("1", 64)
			case "query-pin":
				args[7] = strings.Repeat("2", 64)
			case "request-context":
				f.request.Context[0] ^= 1
				f.write(t)
				stage = "request"
			case "request-overflow":
				if err := os.WriteFile(f.requestPath, bytes.Repeat([]byte(" "), maxExperimentalRequestBytes+1), 0600); err != nil {
					t.Fatal(err)
				}
				stage = "request"
			}
			if os.Remove(f.bundlePath) != nil {
				t.Fatal("fixture")
			}
			r := experimentalCLIReportFor(t, experimentalQueryCommand, args, 70)
			if r.Error == nil || r.Error.Stage != stage || r.Headers != nil {
				t.Fatal("selection mismatch reached the provider bundle")
			}
		})
	}
}

func experimentalCLIGateway() map[string]any {
	return map[string]any{"domainId": 1, "batchId": 1, "protocolVersion": 1, "firstInputSeq": 0, "lastInputSeq": 0,
		"preStateRoot": chain.Hash{}, "postStateRoot": chain.Hash{}, "inputRoot": chain.Hash{}, "receiptRoot": chain.Hash{}, "eventRoot": chain.Hash{}, "outboxRoot": chain.Hash{}, "daHash": chain.Hash{},
		"daMode": 0, "executorPillar": "recorded comparison hint", "submittedAtHeight": 1, "finalizeAtHeight": 1, "assetFlowSummary": nil, "proofData": nil, "state": 0, "isFinalized": true}
}

func TestExperimentalBatchCLIRecordedRefusalWorkflow(t *testing.T) {
	for _, name := range []string{"copied-root", "provider-root", "with-gateway", "wrong-tip", "wrong-header", "evicted", "depth", "signature", "missing-witness", "missing-gateway", "unselected-gateway", "required-gateway-unavailable"} {
		t.Run(name, func(t *testing.T) {
			f := newExperimentalCLIFixture(t)
			args, code, stage := f.args(), 1, "query"
			switch name {
			case "provider-root":
				f.bundle["witness"].(map[string]any)["root"] = chain.Hash{}
			case "with-gateway":
				f.bundle["gateway"] = experimentalCLIGateway()
				args = append(args[:len(args)-1], "--compare-gateway", f.bundlePath)
			case "wrong-tip":
				f.request.TipHash[0] ^= 1
			case "wrong-header":
				f.request.HeaderHash[0] ^= 1
			case "evicted":
				f.request.Height = 12
				code = 2
			case "depth":
				f.request.Height = 14
				f.request.HeaderHash = f.request.TipHash
				code = 2
			case "signature":
				rows := f.bundle["momentums"].([]json.RawMessage)
				var row map[string]json.RawMessage
				if json.Unmarshal(rows[0], &row) != nil {
					t.Fatal("fixture")
				}
				var signature []byte
				if json.Unmarshal(row["signature"], &signature) != nil {
					t.Fatal("fixture")
				}
				signature[0] ^= 1
				row["signature"] = experimentalCLIJSON(t, signature)
				rows[0] = experimentalCLIJSON(t, row)
				stage = "headers"
			case "missing-witness":
				f.bundle["witness"] = nil
				code, stage = 2, "witness"
			case "missing-gateway":
				args = append(args[:len(args)-1], "--compare-gateway", f.bundlePath)
				code, stage = 70, "bundle"
			case "unselected-gateway":
				f.bundle["gateway"] = experimentalCLIGateway()
				code, stage = 70, "bundle"
			case "required-gateway-unavailable":
				f.bundle["gateway"] = nil
				args = append(args[:len(args)-1], "--compare-gateway", f.bundlePath)
				code, stage = 2, "gateway"
			}
			f.write(t)
			before := map[string][]byte{}
			for _, path := range []string{f.configPath, f.requestPath, f.bundlePath} {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				before[path] = raw
			}
			r := experimentalCLIReportFor(t, experimentalQueryCommand, args, code)
			if r.Error == nil || r.Error.Stage != stage {
				t.Fatal("incorrect failure boundary")
			}
			if stage == "query" && (r.Headers == nil || r.Headers.Outcome != "ACCEPT") {
				t.Fatal("recorded signed headers were not accepted before the incompatible witness was refused")
			}
			if stage == "headers" && (r.Headers == nil || r.Headers.Outcome != "REJECT") {
				t.Fatal("altered signature was not rejected")
			}
			for path, raw := range before {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(raw, after) {
					t.Fatal("read-only query changed input")
				}
			}
			files, err := os.ReadDir(filepath.Dir(f.configPath))
			if err != nil || len(files) != 3 {
				t.Fatal("query wrote state or a lock")
			}
		})
	}
}

func TestExperimentalBatchCLIStrictConfigurationAndBundle(t *testing.T) {
	f := newExperimentalCLIFixture(t)
	for _, kind := range []string{"config", "bundle"} {
		original := experimentalCLIJSON(t, f.config)
		if kind == "bundle" {
			original = experimentalCLIJSON(t, f.bundle)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(original, &fields) != nil {
			t.Fatal("fixture")
		}
		for field := range fields {
			for _, change := range []string{"missing", "null", "duplicate", "case-alias"} {
				t.Run(kind+"/"+field+"/"+change, func(t *testing.T) {
					var next map[string]json.RawMessage
					if json.Unmarshal(original, &next) != nil {
						t.Fatal("fixture")
					}
					switch change {
					case "missing":
						delete(next, field)
					case "null":
						next[field] = json.RawMessage("null")
					case "case-alias":
						next[strings.ToUpper(field)] = next[field]
						delete(next, field)
					}
					raw := experimentalCLIJSON(t, next)
					if change == "duplicate" {
						raw = append(raw[:len(raw)-1], append([]byte(","+string(experimentalCLIJSON(t, field))+":"), append(fields[field], '}')...)...)
					}
					if kind == "config" {
						value, err := decodeExperimentalCLIConfig(raw)
						if err == nil || !reflect.DeepEqual(value, experimentalCLIConfig{}) {
							t.Fatal("ambiguous configuration produced partial inputs")
						}
					} else {
						value, err := decodeExperimentalCLIBundle(raw, 3, false)
						if err == nil || !reflect.DeepEqual(value, experimentalCLIBundle{}) {
							t.Fatal("ambiguous provider bundle produced partial inputs")
						}
						if field == "witness" && change == "null" && !errors.Is(err, fetch.ErrCandidateStateUnavailable) {
							t.Fatal("null result was not unavailable")
						}
					}
				})
			}
		}
	}
	config := experimentalCLIJSON(t, f.config)
	for _, raw := range [][]byte{append(bytes.Clone(config), []byte(" {}")...), append(config, '\xff'), bytes.Repeat([]byte(" "), maxExperimentalConfigBytes+1)} {
		if value, err := decodeExperimentalCLIConfig(raw); err == nil || !reflect.DeepEqual(value, experimentalCLIConfig{}) {
			t.Fatal("configuration framing/cap")
		}
	}
	for _, maxHeaders := range []uint32{0, 2, verify.MaxRetainHeaders + 1} {
		if value, err := decodeExperimentalCLIBundle(experimentalCLIJSON(t, f.bundle), maxHeaders, false); err == nil || !reflect.DeepEqual(value, experimentalCLIBundle{}) {
			t.Fatal("header count cap")
		}
	}
	for _, name := range []string{"coverage", "entries"} {
		for _, count := range []int{verify.MaxExperimentalV3ScheduleEntries, verify.MaxExperimentalV3ScheduleEntries + 1} {
			rows := bytes.Repeat([]byte("{},"), count)
			rows = append(rows[:len(rows)-1], ']')
			raw := append([]byte("{\""+name+"\":["), rows...)
			raw = append(raw, '}')
			if (boundExperimentalCLISchedule(raw) == nil) != (count == verify.MaxExperimentalV3ScheduleEntries) {
				t.Fatal("experimental schedule row bound")
			}
		}
	}
}

func TestExperimentalBatchCLIRegularInputBoundsAndIdentity(t *testing.T) {
	dir := t.TempDir()
	path, alternate := filepath.Join(dir, "input.json"), filepath.Join(dir, "alternate.json")
	if os.WriteFile(path, []byte("abc"), 0600) != nil || os.WriteFile(alternate, []byte("abc"), 0600) != nil {
		t.Fatal("fixture")
	}
	for _, limit := range []int64{0, -1, 2, maxExperimentalBundleBytes + 1} {
		called := false
		raw, err := readExperimentalCLIFile(path, limit, func(string) (*os.File, error) { called = true; return nil, io.ErrUnexpectedEOF })
		if err == nil || raw != nil || called {
			t.Fatal("invalid byte cap reached open")
		}
	}
	if raw, err := readExperimentalCLIFile(path, 3, openExperimentalCLIFile); err != nil || string(raw) != "abc" {
		t.Fatal("exact input byte cap", err)
	}
	var opened *os.File
	raw, err := readExperimentalCLIFile(path, 3, func(string) (*os.File, error) { var err error; opened, err = os.Open(alternate); return opened, err })
	if err == nil || raw != nil {
		t.Fatal("replaced identity was read")
	}
	// Windows Stat exposes its native handle error after Close. Read normalizes
	// a closed descriptor to os.ErrClosed on every supported platform.
	if n, err := opened.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatal("refused input descriptor leaked")
	}
	if raw, err := readExperimentalCLIFile(dir, 8, func(string) (*os.File, error) { t.Fatal("directory reached open"); return nil, nil }); err == nil || raw != nil {
		t.Fatal("directory accepted")
	}
}

func TestExperimentalBatchCLIPreopenPathReplacement(t *testing.T) {
	dir := t.TempDir()
	path, replacement := filepath.Join(dir, "input.json"), filepath.Join(dir, "replacement.json")
	// Equal size and bytes leave identity as the only distinguishing property.
	for _, name := range []string{path, replacement} {
		if err := os.WriteFile(name, []byte("abc"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var opened *os.File
	raw, err := readExperimentalCLIFile(path, 3, func(name string) (*os.File, error) {
		if name != path {
			t.Fatal("unexpected selected path")
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Fatal(err)
		}
		var err error
		opened, err = openExperimentalCLIFile(name)
		return opened, err
	})
	if !errors.Is(err, errExperimentalCLIInput) || raw != nil || opened == nil {
		t.Fatal("same-path replacement was not refused after open")
	}
	if n, err := opened.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatal("replacement descriptor leaked")
	}
}

func TestExperimentalBatchCLIDocumentByteBounds(t *testing.T) {
	for _, kind := range []string{"config", "request", "bundle"} {
		t.Run(kind, func(t *testing.T) {
			f := newExperimentalCLIFixture(t)
			path, limit, stage := f.bundlePath, maxExperimentalBundleBytes, "bundle"
			switch kind {
			case "config":
				path, limit, stage = f.configPath, maxExperimentalConfigBytes, "configuration"
			case "request":
				path, limit, stage = f.requestPath, maxExperimentalRequestBytes, "request"
			}
			raw, err := os.ReadFile(path)
			if err != nil || len(raw) > limit {
				t.Fatal("fixture")
			}
			padded := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), limit-len(raw))...)
			if err := os.WriteFile(path, padded, 0600); err != nil {
				t.Fatal(err)
			}
			experimentalCLIReportFor(t, experimentalQueryCommand, f.args(), 1)
			if err := os.WriteFile(path, append(padded, ' '), 0600); err != nil {
				t.Fatal(err)
			}
			r := experimentalCLIReportFor(t, experimentalQueryCommand, f.args(), 70)
			if r.Error == nil || r.Error.Stage != stage || r.Headers != nil {
				t.Fatal("one-over document cap reached header authentication")
			}
		})
	}
}

type experimentalShortWriter struct{ err error }

func (w experimentalShortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, w.err
	}
	return len(p) - 1, w.err
}

func TestExperimentalBatchCLIOutputFailureAndOpaqueString(t *testing.T) {
	f := newExperimentalCLIFixture(t)
	for _, writer := range []io.Writer{experimentalShortWriter{}, experimentalShortWriter{io.ErrClosedPipe}} {
		var diagnostics bytes.Buffer
		if runExperimentalBatch(experimentalConfigCommand, []string{"--config", f.configPath}, writer, &diagnostics) != 70 || !strings.Contains(diagnostics.String(), "cannot write output") {
			t.Fatal("output failure reported success")
		}
	}
	var out, diagnostics bytes.Buffer
	r := experimentalCLIReport{SchemaVersion: 1, Command: experimentalQueryCommand, Result: &verify.ExperimentalBatchEntryResult{Entry: proof.CandidateBatchEntry{ExecutorPillar: string([]byte{0xff})}}}
	if finishExperimentalBatch(r, 0, &out, &diagnostics) != 70 {
		t.Fatal("lossy ABI JSON reported success")
	}
	var value experimentalCLIReport
	if json.Unmarshal(out.Bytes(), &value) != nil || value.ExitCode != 70 || value.Status != "error" || value.Result != nil || value.Error == nil || value.Error.Stage != "output" || diagnostics.Len() != 0 {
		t.Fatal("opaque string did not produce a clean error envelope")
	}
}

func TestExperimentalBatchCLICompiledWorkflow(t *testing.T) {
	f := newExperimentalCLIFixture(t)
	name := "zenon-spv"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(t.TempDir(), name)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if raw, err := exec.CommandContext(ctx, "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v %s", err, raw)
	}
	for _, command := range []string{experimentalConfigCommand, experimentalQueryCommand} {
		args, want := []string{command, "--config", f.configPath}, 0
		if command == experimentalQueryCommand {
			args, want = append([]string{command}, f.args()...), 1
		}
		cmd := exec.CommandContext(ctx, binary, args...)
		var out, diagnostics bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &diagnostics
		err := cmd.Run()
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal(err)
			}
			code = exit.ExitCode()
		}
		var report experimentalCLIReport
		if code != want || json.Unmarshal(out.Bytes(), &report) != nil || report.ExitCode != want || diagnostics.Len() != 0 || report.Result != nil || report.ProductionStateValueGuarantee {
			t.Fatal("compiled CLI boundary", code, out.String(), diagnostics.String())
		}
		if command == experimentalQueryCommand && (report.Headers == nil || report.Headers.Outcome != "ACCEPT" || report.Error == nil || report.Error.Category != "invalid_witness") {
			t.Fatal("compiled command did not bind the incompatible proof to recorded accepted headers")
		}
	}
}
