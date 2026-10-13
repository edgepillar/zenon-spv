package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// This peer serves only the original momentum bytes and one recorded account
// observation. It cannot select a frontier, a trust input or a consumer target.
func basicObserverPeer(t *testing.T, c accountSegmentCorpus, address string, start uint64, account json.RawMessage, selectedHeights bool) (string, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	var momentumCalls, accountCalls atomic.Int32
	first := c.Chain.Vectors[0].Header.Height
	last := c.Chain.Vectors[len(c.Chain.Vectors)-1].Header.Height
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		user, password, authenticated := r.BasicAuth()
		var id uint64
		if r.Method != http.MethodPost || !authenticated || user != "PRIVATE_BASIC_USER" || password != "PRIVATE_BASIC_PASSWORD" ||
			r.URL.Query().Get("token") != "PRIVATE_BASIC_QUERY" || json.NewDecoder(r.Body).Decode(&request) != nil ||
			request.JSONRPC != "2.0" || json.Unmarshal(request.ID, &id) != nil || id == 0 {
			t.Error("loopback request differs from its fixed read-only configuration")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var list []json.RawMessage
		switch request.Method {
		case "ledger.getMomentumsByHeight":
			call := momentumCalls.Add(1)
			wantedStart, wantedCount := first, last-first+1
			if selectedHeights {
				wantedCount = 1
				if call == 2 {
					wantedStart = last
				}
			}
			want, err := json.Marshal([]any{wantedStart, wantedCount})
			if err != nil || !bytes.Equal(request.Params, want) || call > 1 && !selectedHeights || call > 2 {
				t.Error("collector changed or repeated the selected momentum request")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			for i := uint64(0); i < wantedCount; i++ {
				list = append(list, c.Chain.Vectors[wantedStart-first+i].Momentum)
			}
		case "ledger.getAccountBlocksByHeight":
			want, err := json.Marshal([]any{address, start, uint64(1)})
			if err != nil || !bytes.Equal(request.Params, want) || accountCalls.Add(1) != 1 {
				t.Error("collector changed or repeated the independently selected account range")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			list = []json.RawMessage{account}
		default:
			t.Error("collector requested an unselected RPC method")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": map[string]any{"list": list}}) != nil {
			t.Error("cannot return selected loopback bytes")
		}
	}))
	t.Cleanup(server.Close)
	endpoint := strings.Replace(server.URL, "http://", "http://PRIVATE_BASIC_USER:PRIVATE_BASIC_PASSWORD@", 1) + "?token=PRIVATE_BASIC_QUERY"
	return endpoint, &calls
}

// The recorded node outcome selects neither expectations nor trust. Ordinary
// collector, verifier, consumer and observer binaries exercise the whole path.
func TestCompiledNodeAccountBasicObserver(t *testing.T) {
	bins := buildQueryCLIs(t, "fetch-bundle", "zenon-spv", "consume-query-report", "observe-block")
	hashes := make(map[string]string)
	for name, path := range bins {
		digest := sha256.Sum256(readCLIFile(t, path))
		hashes[name] = hex.EncodeToString(digest[:])
	}
	input := readCLIFile(t, "../testdata/conformance/account-segments.json")
	digest := sha256.Sum256(input)
	if hex.EncodeToString(digest[:]) != "1faca6715c3865bae726a7a07f56ef2c43bd8a5a5c9816f618373312de43b048" {
		t.Fatal("original signed account selection changed")
	}
	c := loadNodeAccountCorpus(t, "account-segments.json")
	user := accountBasicRPCUser(t)
	headers := make([]chain.Header, len(c.Chain.Vectors))
	var entries []verify.ProducerEntry
	for i, vector := range c.Chain.Vectors {
		headers[i] = vector.Header
		entries = append(entries, verify.ProducerEntry{Height: vector.Header.Height, TimestampUnix: vector.Header.TimestampUnix,
			ProducingAddr: chain.PubKeyToAddress(vector.Header.PublicKey)})
	}
	last := headers[len(headers)-1]
	opts := verify.VerifyOptions{Policy: verify.DefaultPolicy()}
	opts.Policy.RetainHeaders = 16
	opts.Policy.ProtocolProfile = &verify.ProtocolProfile{Version: 1, Anchor: c.Chain.Anchor, ValidThrough: last.Height,
		Source: "PRIVATE_BASIC_OBSERVER_PROFILE"}
	schedule, err := verify.NewProducerSchedule(c.Chain.Anchor.ChainID,
		[]verify.ProducerCoverage{{FromHeight: headers[0].Height, ThroughHeight: last.Height}}, entries, nil, nil)
	if err != nil {
		t.Fatal("cannot select synthetic producer coverage")
	}
	opts.ProducerAuth = verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired, Authorizer: verify.NewScheduleAuthorizer(schedule)}
	initial, err := verify.NewVerifiedState(c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal("cannot prepare the original anchor and explicit policy")
	}
	accepted, retained := initial.Extend(headers)
	if accepted.Outcome != verify.OutcomeAccept {
		t.Fatal("original signed headers did not satisfy the selected policy")
	}
	selectedContext, err := retained.VerificationContext()
	if err != nil || selectedContext.Fingerprint == nil {
		t.Fatal("missing independently selected context")
	}
	pin := hex.EncodeToString(selectedContext.Fingerprint[:])
	dir := t.TempDir()
	anchorPath := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", c.Chain.Anchor)
	profilePath := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", opts.Policy.ProtocolProfile)
	schedulePath := writeCLIJSON(t, dir, "PRIVATE_SCHEDULE.json", schedule)
	statePath := filepath.Join(dir, "PRIVATE_RETAINED_STATE.json")
	initialPath := filepath.Join(dir, "PRIVATE_ANCHOR_STATE.json")
	if retained.Save(statePath) != nil || initial.Save(initialPath) != nil {
		t.Fatal("cannot preserve independently selected states")
	}
	private := filepath.Join(dir, "PRIVATE_RECORDS")
	if os.Mkdir(private, 0o700) != nil {
		t.Fatal("cannot prepare protected observation parent")
	}
	var guards []func()
	for _, path := range []string{anchorPath, profilePath, schedulePath, statePath, initialPath} {
		guards = append(guards, protectCLIState(t, path))
	}
	check := func(t *testing.T, row accountBasicObservation, mode string) {
		t.Helper()
		start := uint64(1)
		if strings.HasPrefix(row.Profile, "height-two-") {
			start = 2
		}
		endpoint, calls := basicObserverPeer(t, c, user.RPCAddress, start, row.Wire, mode == "missing-collected-proof")
		selectedState := statePath
		tip := chain.HashHeight{Height: last.Height, Hash: last.HeaderHash}
		target := user.Vectors[0].Block.AccountHeader()
		if mode == "missing-retained-header" {
			selectedState = initialPath
			tip = chain.HashHeight{Height: c.Chain.Anchor.Height, Hash: c.Chain.Anchor.HeaderHash}
		}
		if mode == "wrong-selected-target" {
			target = user.Vectors[1].Block.AccountHeader()
		}
		if mode == "wrong-selected-tip" {
			h := headers[len(headers)-2]
			tip = chain.HashHeight{Height: h.Height, Hash: h.HeaderHash}
		}
		// These bytes are selected from the original signed fixture before the
		// application collects anything. They never come from its report/bundle.
		expectations := map[string]any{"schema_version": 1, "command": "verify-segment", "context_fingerprint": pin,
			"verification_tip":    tip,
			"targets":             []any{map[string]any{"scope": "segment", "index": 0, "block_index": 0, "account_header": target}},
			"required_guarantees": []string{"CONTENT_INCLUSION", "SIGNATURE_AUTHENTICITY"},
			"allowed_trust_assumptions": []string{"TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_RETAINED_WINDOW_DEPTH",
				"TRUST_EXTERNAL_PROTOCOL_PROFILE", "TRUST_EXTERNAL_PRODUCER_SCHEDULE"}}
		expectedPath := writeCLIJSON(t, t.TempDir(), "PRIVATE_EXPECTATIONS.json", expectations)
		guardExpected := protectCLIState(t, expectedPath)
		args := []string{"--collector", bins["fetch-bundle"], "--collector-sha256", hashes["fetch-bundle"],
			"--rpc", endpoint, "--height", strconv.FormatUint(last.Height, 10), "--count", strconv.Itoa(len(headers) - 1),
			"--segments", user.RPCAddress + ":" + strconv.FormatUint(start, 10),
			"--verifier", bins["zenon-spv"], "--verifier-sha256", hashes["zenon-spv"],
			"--consumer", bins["consume-query-report"], "--consumer-sha256", hashes["consume-query-report"],
			"--command", "verify-segment", "--genesis-config", anchorPath, "--protocol-profile", profilePath, "--schedule", schedulePath,
			"--state", selectedState, "--expectations", expectedPath, "--private-dir", private, "--expect-context", pin,
			"--window", "low", "--retain-headers", "16"}
		if mode == "missing-collected-proof" {
			// Preserve every signed momentum byte; explicitly omit all original
			// confirming heights instead of fabricating a different commitment.
			args = append(args, "--momentum-heights", strconv.FormatUint(last.Height, 10))
		}
		collector, verifier, consumer := int64(1), (*int64)(nil), (*int64)(nil)
		outer, category, count := 2, "process_failure", 0
		switch row.Profile {
		case "first-exact-ack", "stored-chain-mismatch", "ack-missing", "ack-wrong-hash", "ack-corrupt-entry":
			collector, verifier, consumer = 0, int64Pointer(0), int64Pointer(0)
			outer, category, count = 0, "", 1
		case "signature-empty":
			// Invalid signatures reject (exit 1); missing evidence refuses (2).
			collector, verifier = 0, int64Pointer(1)
		}
		switch mode {
		case "missing-retained-header", "missing-collected-proof":
			verifier, consumer, outer, category, count = int64Pointer(2), nil, 2, "process_failure", 0
		case "wrong-selected-target":
			consumer, outer, category, count = int64Pointer(2), 2, "target_mismatch", 0
		case "wrong-selected-tip":
			consumer, outer, category, count = int64Pointer(2), 2, "report_mismatch", 0
		}
		result := runQueryCLI(t, bins["observe-block"], args...)
		var report struct {
			Version   int                   `json:"schema_version"`
			Status    string                `json:"status"`
			Category  *string               `json:"category"`
			Count     int                   `json:"checked_targets"`
			ElapsedNS int64                 `json:"elapsed_ns"`
			Collector observerProcessRecord `json:"collector"`
			Verifier  observerProcessRecord `json:"verifier"`
			Consumer  observerProcessRecord `json:"consumer"`
		}
		if result.code != outer || len(result.stderr) != 0 || json.Unmarshal(result.stdout, &report) != nil ||
			report.Version != 2 || report.Count != count || report.ElapsedNS < 0 || len(losslessObject(t, result.stdout)) != 8 ||
			report.Collector.ExitCode == nil || *report.Collector.ExitCode != collector {
			t.Fatalf("recorded observation lost its selected process boundary: exit=%d targets=%d collector=%v", result.code, report.Count, report.Collector.ExitCode)
		}
		for _, child := range []struct {
			got  observerProcessRecord
			want *int64
		}{{report.Verifier, verifier}, {report.Consumer, consumer}} {
			if (child.got.ExitCode == nil) != (child.want == nil) || child.want != nil && *child.got.ExitCode != *child.want {
				t.Fatalf("later child exit differs: got=%s want=%s", marshalCLIValue(t, child.got.ExitCode), marshalCLIValue(t, child.want))
			}
		}
		if outer == 0 {
			if report.Status != "matched" || report.Category != nil {
				t.Fatal("original independently selected target did not match")
			}
		} else if report.Status != "not_matched" || report.Category == nil || *report.Category != category {
			t.Fatal("failed observation lost its selected refusal category")
		}
		if collector != 0 && report.Collector.StdoutBytes != 0 {
			t.Fatal("failed complete collection published a partial bundle")
		}
		wantCalls := int32(2)
		if mode == "missing-collected-proof" {
			wantCalls = 3
		}
		if calls.Load() != wantCalls {
			t.Fatal("collection retried, selected a frontier or omitted a request")
		}
		for _, child := range []observerProcessRecord{report.Collector, report.Verifier, report.Consumer} {
			if child.ElapsedNS < 0 || child.StdoutBytes < 0 || child.StderrBytes < 0 ||
				child.ExitCode == nil && (child.ElapsedNS != 0 || child.StdoutBytes != 0 || child.StderrBytes != 0) {
				t.Fatal("resource fields contradict actual child execution")
			}
		}
		for _, secret := range []string{"PRIVATE", endpoint, dir, pin, user.RPCAddress, hashes["fetch-bundle"], hashes["zenon-spv"], hashes["consume-query-report"]} {
			if bytes.Contains(result.stdout, []byte(secret)) {
				t.Fatal("observer reproduced a private input or child diagnostic")
			}
		}
		for _, guard := range guards {
			guard()
		}
		guardExpected()
		for _, path := range []string{statePath, initialPath} {
			if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
				t.Fatal("read-only observation obtained writer ownership")
			}
		}
		files, err := os.ReadDir(private)
		if err != nil || len(files) != 0 {
			t.Fatal("observation left raw private files")
		}
	}
	rows := loadAccountBasicObservations(t)
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) { check(t, row, "") })
	}
	positives := 0
	for _, row := range rows {
		if row.Profile != "first-exact-ack" {
			continue
		}
		if row.NodeResult != "MATCH" {
			t.Fatal("missing recorded positive node method control")
		}
		positives++
		for _, mode := range []string{"missing-retained-header", "missing-collected-proof", "wrong-selected-target", "wrong-selected-tip"} {
			t.Run(fmt.Sprintf("%s/%s", row.Name, mode), func(t *testing.T) { check(t, row, mode) })
		}
	}
	if positives != 2 {
		t.Fatal("both recorded node entry points must exercise independent selections")
	}
}
