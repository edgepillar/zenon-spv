package conformance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/statelock"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Each invocation starts ordinary watch/collector/verifier/consumer processes.
// Signed header/account bytes are node-derived; trust, frontier hints and all
// faults are local fixtures, not a live network or independently selected pilot.
func TestCompiledAdvancingBlockObserver(t *testing.T) {
	bins := buildQueryCLIs(t, "fetch-bundle", "zenon-spv", "consume-query-report", "observe-block")
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("advancing report consumption requires Python 3.9+")
	}
	reader, err := filepath.Abs(filepath.Join("..", "..", "tools", "consume-observer-report.py"))
	if err != nil {
		t.Fatal(err)
	}
	readerHash := sha256.Sum256(readCLIFile(t, reader))
	t.Logf("advancing-observer-reader {\"sha256\":\"%s\"}", hex.EncodeToString(readerHash[:]))
	hashes := make(map[string]string)
	for name, path := range bins {
		sum := sha256.Sum256(readCLIFile(t, path))
		hashes[name] = hex.EncodeToString(sum[:])
	}
	c, bundle := contractBatchBundle(t)
	headers := bundle.Headers
	makeSelection := func(t *testing.T, through uint64, endpoint string) ([]string, string, verify.VerifyOptions, []func()) {
		t.Helper()
		opts := verify.VerifyOptions{Policy: verify.DefaultPolicy()}
		opts.Policy.RetainHeaders = 16
		opts.Policy.ProtocolProfile = &verify.ProtocolProfile{Version: 1, Anchor: c.Chain.Anchor,
			ValidThrough: through, Source: "PRIVATE_ADVANCING_PROFILE"}
		entries := []verify.ProducerEntry{}
		for _, h := range headers {
			entries = append(entries, verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
		}
		schedule, err := verify.NewProducerSchedule(c.Chain.Anchor.ChainID,
			[]verify.ProducerCoverage{{FromHeight: headers[0].Height, ThroughHeight: headers[len(headers)-1].Height}}, entries, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		opts.ProducerAuth = verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired, Authorizer: verify.NewScheduleAuthorizer(schedule)}
		state, err := verify.NewVerifiedState(c.Chain.Anchor, opts)
		if err != nil {
			t.Fatal(err)
		}
		accepted, state := state.Extend(headers[:6])
		if accepted.Outcome != verify.OutcomeAccept {
			t.Fatal("selected initial signed prefix refused")
		}
		context, err := state.VerificationContext()
		if err != nil || context.Fingerprint == nil {
			t.Fatal("missing selected context")
		}
		pin := hex.EncodeToString(context.Fingerprint[:])
		dir := t.TempDir()
		anchor := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", c.Chain.Anchor)
		profile := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", opts.Policy.ProtocolProfile)
		producers := writeCLIJSON(t, dir, "PRIVATE_PRODUCERS.json", schedule)
		statePath := filepath.Join(dir, "PRIVATE_STATE.json")
		if err := state.Save(statePath); err != nil {
			t.Fatal(err)
		}
		refs := []any{}
		for i, evidence := range bundle.Commitments {
			refs = append(refs, map[string]any{"scope": "segment", "index": 0, "block_index": i, "account_header": evidence.Target})
		}
		expectations := writeCLIJSON(t, dir, "PRIVATE_EXPECTATIONS.json", map[string]any{
			"schema_version": 1, "command": "verify-segment", "context_fingerprint": pin,
			"verification_tip": map[string]any{"hash": headers[8].HeaderHash, "height": headers[8].Height},
			"targets":          refs, "required_guarantees": []string{"CONTENT_INCLUSION"},
			"allowed_trust_assumptions": []string{"TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_RETAINED_WINDOW_DEPTH", "TRUST_EXTERNAL_PROTOCOL_PROFILE", "TRUST_EXTERNAL_PRODUCER_SCHEDULE"}})
		private := filepath.Join(dir, "PRIVATE_STAGING")
		if err := os.Mkdir(private, 0o700); err != nil {
			t.Fatal(err)
		}
		guards := []func(){protectCLIState(t, anchor), protectCLIState(t, profile), protectCLIState(t, producers), protectCLIState(t, expectations)}
		args := []string{"--advance-state-once", "--watch-safety-margin", "1", "--watch-batch-size", "1",
			"--collector", bins["fetch-bundle"], "--collector-sha256", hashes["fetch-bundle"], "--rpc", endpoint,
			"--height", "4009", "--count", "8", "--segments", c.Segments[0].RPCAddress + ":1-5",
			"--verifier", bins["zenon-spv"], "--verifier-sha256", hashes["zenon-spv"],
			"--consumer", bins["consume-query-report"], "--consumer-sha256", hashes["consume-query-report"],
			"--command", "verify-segment", "--genesis-config", anchor, "--protocol-profile", profile,
			"--schedule", producers, "--state", statePath, "--expectations", expectations, "--private-dir", private,
			"--expect-context", pin, "--window", "low", "--retain-headers", "16"}
		return args, statePath, opts, guards
	}
	type advancingReport struct {
		Version   int                    `json:"schema_version"`
		Status    string                 `json:"status"`
		Category  *string                `json:"category"`
		Count     int                    `json:"checked_targets"`
		Watch     *observerProcessRecord `json:"watch"`
		Collector *observerProcessRecord `json:"collector"`
		Verifier  observerProcessRecord  `json:"verifier"`
		Consumer  observerProcessRecord  `json:"consumer"`
	}
	check := func(t *testing.T, args []string, statePath string, opts verify.VerifyOptions, guards []func(), want int, tipIndex int, watchExit int64, collected, queried bool) {
		t.Helper()
		result := runQueryCLI(t, bins["observe-block"], args...)
		var report advancingReport
		if result.code != want || len(result.stderr) != 0 || json.Unmarshal(result.stdout, &report) != nil ||
			report.Version != 3 || len(losslessObject(t, result.stdout)) != 9 || report.Watch == nil || report.Collector == nil ||
			report.Watch.ExitCode == nil || *report.Watch.ExitCode != watchExit ||
			(report.Collector.ExitCode != nil) != collected || (report.Verifier.ExitCode != nil) != queried {
			t.Fatalf("advancing workflow metadata mismatch: actual=%d expected=%d report=%s", result.code, want, result.stdout)
		}
		if want == 0 {
			if report.Status != "matched" || report.Category != nil || report.Count != 5 || report.Consumer.ExitCode == nil || *report.Consumer.ExitCode != 0 {
				t.Fatal("advancing observation lost complete strict consumption")
			}
		} else if report.Status != "not_matched" || report.Category == nil || report.Count != 0 || report.Consumer.ExitCode != nil {
			t.Fatal("refused advancement or query acquired a consumer match")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, python, "-I", "-B", reader, "--mode", "advancing", "--observer-exit-code", strconv.Itoa(result.code), "--expected-targets", "5")
		cmd.Stdin = bytes.NewReader(result.stdout)
		var consumed, diagnostics bytes.Buffer
		cmd.Stdout, cmd.Stderr, cmd.WaitDelay = &consumed, &diagnostics, time.Second
		readerErr := cmd.Run()
		if ctx.Err() != nil || diagnostics.Len() != 0 || consumed.Len() > 1024 {
			t.Fatal("actual advancing report consumption did not complete privately")
		}
		// Python's native text stdout uses CRLF on Windows. Keep the exact
		// fixed JSON bytes and permit only these two complete line endings.
		matches := func(value string) bool {
			return consumed.String() == value+"\n" || consumed.String() == value+"\r\n"
		}
		if want == 0 {
			if readerErr != nil || !matches("{\"schema_version\":1,\"status\":\"matched\",\"category\":null,\"checked_targets\":5}") {
				t.Fatal("independent reader did not match the actual complete advancing diagnostic")
			}
		} else {
			var exit *exec.ExitError
			if !errors.As(readerErr, &exit) || exit.ExitCode() != 2 || !matches("{\"schema_version\":1,\"status\":\"not_matched\",\"category\":\"process_failure\",\"checked_targets\":0}") {
				t.Fatal("independent reader exit or fixed refusal output differed")
			}
		}
		resumed, err := verify.LoadTrustedState(statePath, c.Chain.Anchor, opts)
		if tip, ok := resumed.Tip(); err != nil || !ok || tip.Height != headers[tipIndex].Height || tip.HeaderHash != headers[tipIndex].HeaderHash {
			t.Fatal("new process did not reload the independently selected actual saved tip")
		}
		lock, err := statelock.Acquire(statePath)
		if err != nil {
			t.Fatal("bounded watch retained writer ownership")
		}
		if lock.Close() != nil {
			t.Fatal("cannot release test writer lock")
		}
		for _, guard := range guards {
			guard()
		}
		staging := args[slices.Index(args, "--private-dir")+1]
		if entries, err := os.ReadDir(staging); err != nil || len(entries) != 0 {
			t.Fatal("advancing observation left private raw files")
		}
		for _, secret := range []string{"PRIVATE", statePath, args[slices.Index(args, "--rpc")+1], args[slices.Index(args, "--expect-context")+1], c.Segments[0].RPCAddress} {
			if bytes.Contains(result.stdout, []byte(secret)) {
				t.Fatal("advancing summary disclosed private selections")
			}
		}
	}
	peer := newQueryCLIPeer(t, c, false, headers[8])
	args, statePath, opts, guards := makeSelection(t, 4009, peer.url)
	for _, tc := range []struct {
		name string
		tip  int
		code int
	}{
		{"partial_progress_delayed_query_refused", 6, 2},
		{"restart_advances_another_bounded_prefix", 7, 2},
		{"restart_reaches_selected_tip_and_matches_all_targets", 8, 0},
		{"caught_up_rechecks_same_selected_targets", 8, 0},
	} {
		t.Run(tc.name, func(t *testing.T) { check(t, args, statePath, opts, guards, tc.code, tc.tip, 0, true, true) })
	}
	for _, tc := range []struct {
		name       string
		fault      int32
		through    uint64
		watchExit  int64
		stale      bool
		disconnect bool
	}{
		{"disconnected_peer_stops_before_collection", 0, 4009, 2, false, true},
		{"malformed_peer_stops_before_collection", 7, 4009, 2, false, false},
		{"case_aliased_range_stops_before_collection", 1, 4009, 2, false, false},
		{"profile_expiry_does_not_renew_or_advance", 0, 4006, 2, false, false},
		{"stale_peer_cannot_supply_selected_query_tip", 0, 4009, 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selectedPeer := newQueryCLIPeer(t, c, false, headers[8])
			if tc.stale {
				selectedPeer = newQueryCLIPeer(t, c, false, headers[5])
			}
			selectedPeer.rangeFault.Store(tc.fault)
			endpoint := selectedPeer.url
			if tc.disconnect {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
				t.Cleanup(server.Close)
				endpoint = server.URL
			}
			selected, path, settings, protections := makeSelection(t, tc.through, endpoint)
			selected = selectQueryCLIOption(selected, "--watch-batch-size", "16")
			before := readCLIFile(t, path)
			check(t, selected, path, settings, protections, 2, 5, tc.watchExit, tc.stale, tc.stale)
			if !bytes.Equal(before, readCLIFile(t, path)) {
				t.Fatal("failed or stale tick changed the selected header state")
			}
		})
	}
}
