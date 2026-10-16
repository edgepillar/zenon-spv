package conformance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/statelock"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Exercise ordinary executables through real file replacement and process
// boundaries. The headers/accounts are signed node-corpus bytes; the schedule,
// frontier and deliberately failed destinations are local test selections.
func TestCompiledAdvancingObserverPersistence(t *testing.T) {
	bins := buildQueryCLIs(t, "fetch-bundle", "zenon-spv", "consume-query-report", "observe-block")
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("persistence report consumption requires Python 3.9+")
	}
	reader, err := filepath.Abs(filepath.Join("..", "..", "tools", "consume-observer-report.py"))
	if err != nil {
		t.Fatal(err)
	}
	readerHash := sha256.Sum256(readCLIFile(t, reader))
	t.Logf("advancing-persistence-reader {\"sha256\":\"%s\"}", hex.EncodeToString(readerHash[:]))
	corpus, bundle := contractBatchBundle(t)
	headers := bundle.Headers
	makeFixture := func(t *testing.T, failSave, failCollector bool) *advancingPersistenceFixture {
		t.Helper()
		opts := verify.VerifyOptions{Policy: verify.DefaultPolicy()}
		opts.Policy.RetainHeaders = 16
		opts.Policy.ProtocolProfile = &verify.ProtocolProfile{Version: 1, Anchor: corpus.Chain.Anchor,
			ValidThrough: headers[8].Height, Source: "PRIVATE_PERSISTENCE_PROFILE"}
		entries := make([]verify.ProducerEntry, 0, len(headers))
		for _, h := range headers {
			entries = append(entries, verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
		}
		schedule, err := verify.NewProducerSchedule(corpus.Chain.Anchor.ChainID,
			[]verify.ProducerCoverage{{FromHeight: headers[0].Height, ThroughHeight: headers[8].Height}}, entries, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		opts.ProducerAuth = verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired, Authorizer: verify.NewScheduleAuthorizer(schedule)}
		state, err := verify.NewVerifiedState(corpus.Chain.Anchor, opts)
		if err != nil {
			t.Fatal(err)
		}
		accepted, state := state.Extend(headers[:6])
		if accepted.Outcome != verify.OutcomeAccept {
			t.Fatal("selected initial prefix refused")
		}
		settings, err := state.VerificationContext()
		if err != nil || settings.Fingerprint == nil {
			t.Fatal("selected context unavailable")
		}
		pin := hex.EncodeToString(settings.Fingerprint[:])
		dir := t.TempDir()
		f := &advancingPersistenceFixture{
			bins: bins, python: python, reader: reader, anchor: corpus.Chain.Anchor, opts: opts, headers: headers,
			state: filepath.Join(dir, "PRIVATE_STATE.json"), staging: filepath.Join(dir, "PRIVATE_STAGING"),
		}
		if err := state.Save(f.state); err != nil {
			t.Fatal(err)
		}
		initialLock, err := statelock.Acquire(f.state)
		if err != nil || initialLock.Close() != nil {
			t.Fatal("cannot prepare the persistent writer companion")
		}
		lockInfo, err := os.Stat(f.state + ".lock")
		if err != nil {
			t.Fatal(err)
		}
		lockBytes := readCLIFile(t, f.state+".lock")
		if err := os.Mkdir(f.staging, 0o700); err != nil {
			t.Fatal(err)
		}
		anchor := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", corpus.Chain.Anchor)
		profile := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", opts.Policy.ProtocolProfile)
		producers := writeCLIJSON(t, dir, "PRIVATE_PRODUCERS.json", schedule)
		targets := []any{}
		for i, evidence := range bundle.Commitments {
			targets = append(targets, map[string]any{"scope": "segment", "index": 0, "block_index": i, "account_header": evidence.Target})
		}
		expectations := map[string]any{
			"schema_version": 1, "command": "verify-segment", "context_fingerprint": pin,
			"verification_tip": map[string]any{"hash": headers[8].HeaderHash, "height": headers[8].Height},
			"targets":          targets, "required_guarantees": []string{"CONTENT_INCLUSION"},
			"allowed_trust_assumptions": []string{"TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_RETAINED_WINDOW_DEPTH", "TRUST_EXTERNAL_PROTOCOL_PROFILE", "TRUST_EXTERNAL_PRODUCER_SCHEDULE"},
		}
		selected := writeCLIJSON(t, dir, "PRIVATE_EXPECTATIONS.json", expectations)
		expectations["verification_tip"] = map[string]any{"hash": headers[7].HeaderHash, "height": headers[7].Height}
		f.wrongExpectations = writeCLIJSON(t, dir, "PRIVATE_DIFFERENT_TIP.json", expectations)
		f.guards = []func(){protectCLIState(t, anchor), protectCLIState(t, profile), protectCLIState(t, producers),
			protectCLIState(t, selected), protectCLIState(t, f.wrongExpectations), func() {
				// A writer companion must stay writable; the read-only input
				// guard deliberately changes permissions and is unsuitable here.
				current, err := os.Stat(f.state + ".lock")
				if err != nil || !os.SameFile(lockInfo, current) || lockInfo.Mode() != current.Mode() ||
					!lockInfo.ModTime().Equal(current.ModTime()) || !bytes.Equal(lockBytes, readCLIFile(t, f.state+".lock")) {
					t.Fatal("writer companion was removed, replaced or changed")
				}
			}}
		peer := newQueryCLIPeer(t, corpus, false, headers[8])
		var afterRange func() error
		if failSave {
			f.backup = filepath.Join(dir, "PRIVATE_BEFORE_SAVE.json")
			afterRange = func() error {
				// The watch has loaded state and is requesting the signed
				// extension. Keep its companion lock and parent unchanged.
				if err := os.Rename(f.state, f.backup); err != nil {
					return err
				}
				return os.Mkdir(f.state, 0o700)
			}
		}
		f.relay = newAdvancingPersistenceRelay(t, peer.url, afterRange, failCollector)
		pins := make(map[string]string)
		for name, path := range bins {
			sum := sha256.Sum256(readCLIFile(t, path))
			pins[name] = hex.EncodeToString(sum[:])
		}
		f.args = []string{"--advance-state-once", "--watch-safety-margin", "1", "--watch-batch-size", "16",
			"--collector", bins["fetch-bundle"], "--collector-sha256", pins["fetch-bundle"], "--rpc", f.relay.url,
			"--height", "4009", "--count", "8", "--momentum-heights", "4003", "--segments", corpus.Segments[0].RPCAddress + ":1-5",
			"--verifier", bins["zenon-spv"], "--verifier-sha256", pins["zenon-spv"],
			"--consumer", bins["consume-query-report"], "--consumer-sha256", pins["consume-query-report"],
			"--command", "verify-segment", "--genesis-config", anchor, "--protocol-profile", profile,
			"--schedule", producers, "--state", f.state, "--expect-context", pin,
			"--window", "low", "--retain-headers", "16", "--expectations", selected, "--private-dir", f.staging}
		return f
	}
	t.Run("busy_writer_stops_before_rpc", func(t *testing.T) {
		f := makeFixture(t, false, false)
		before := readCLIFile(t, f.state)
		lock, err := statelock.Acquire(f.state)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.Close() }()
		f.check(t, f.args, 2, [4]*int64{int64Pointer(70), nil, nil, nil})
		if f.relay.calls.Load() != 0 || !bytes.Equal(before, readCLIFile(t, f.state)) {
			t.Fatal("busy writer queried peers or changed state")
		}
		if lock.Close() != nil {
			t.Fatal("cannot release selected writer")
		}
		f.finish(t, 5, 0, 0)
	})
	saveFault := makeFixture(t, true, false)
	beforeSave := readCLIFile(t, saveFault.state)
	if !t.Run("failed_state_replacement_stops_before_collection", func(t *testing.T) {
		saveFault.check(t, saveFault.args, 2, [4]*int64{int64Pointer(70), nil, nil, nil})
		info, err := os.Stat(saveFault.state)
		if err != nil || !info.IsDir() || !saveFault.relay.afterRangeDone.Load() ||
			!bytes.Equal(beforeSave, readCLIFile(t, saveFault.backup)) || saveFault.relay.calls.Load() != 3 {
			t.Fatal("selected save destination did not fail after state load")
		}
		entries, err := os.ReadDir(saveFault.state)
		if err != nil || len(entries) != 0 {
			t.Fatal("failed save published data into the unavailable destination")
		}
		if err := os.Remove(saveFault.state); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(saveFault.backup, saveFault.state); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(beforeSave, readCLIFile(t, saveFault.state)) {
			t.Fatal("explicit fault removal changed the saved prefix")
		}
		saveFault.finish(t, 5, 0, 3)
	}) {
		t.FailNow()
	}
	t.Run("explicit_restart_after_save_fault_extends_old_prefix", func(t *testing.T) {
		calls := saveFault.relay.calls.Load()
		saveFault.check(t, saveFault.args, 0, [4]*int64{int64Pointer(0), int64Pointer(0), int64Pointer(0), int64Pointer(0)})
		saveFault.finish(t, 8, calls, 6)
		if saveFault.relay.ranges.Load() != 2 {
			t.Fatal("explicit restart did not fetch the unpersisted prefix again")
		}
	})
	collectionFault := makeFixture(t, false, true)
	if !t.Run("collector_failure_preserves_saved_progress", func(t *testing.T) {
		collectionFault.check(t, collectionFault.args, 2, [4]*int64{int64Pointer(0), int64Pointer(1), nil, nil})
		if !collectionFault.relay.collectorFaultDone.Load() || collectionFault.relay.calls.Load() != 4 {
			t.Fatal("collector fault did not follow one completed watch")
		}
		collectionFault.finish(t, 8, 0, 4)
	}) {
		t.FailNow()
	}
	t.Run("explicit_restart_after_collection_failure_uses_saved_prefix", func(t *testing.T) {
		before := readCLIFile(t, collectionFault.state)
		calls := collectionFault.relay.calls.Load()
		collectionFault.check(t, collectionFault.args, 0, [4]*int64{int64Pointer(0), int64Pointer(0), int64Pointer(0), int64Pointer(0)})
		if !bytes.Equal(before, readCLIFile(t, collectionFault.state)) || collectionFault.relay.ranges.Load() != 1 {
			t.Fatal("caught-up restart rolled back or fetched the already saved prefix")
		}
		collectionFault.finish(t, 8, calls, 5)
	})
	consumerFault := makeFixture(t, false, false)
	if !t.Run("consumer_tip_mismatch_preserves_saved_progress", func(t *testing.T) {
		args := selectQueryCLIOption(consumerFault.args, "--expectations", consumerFault.wrongExpectations)
		consumerFault.check(t, args, 2, [4]*int64{int64Pointer(0), int64Pointer(0), int64Pointer(0), int64Pointer(2)})
		consumerFault.finish(t, 8, 0, 6)
	}) {
		t.FailNow()
	}
	t.Run("explicit_restart_with_preselected_tip_matches_saved_progress", func(t *testing.T) {
		before := readCLIFile(t, consumerFault.state)
		calls := consumerFault.relay.calls.Load()
		consumerFault.check(t, consumerFault.args, 0, [4]*int64{int64Pointer(0), int64Pointer(0), int64Pointer(0), int64Pointer(0)})
		if !bytes.Equal(before, readCLIFile(t, consumerFault.state)) || consumerFault.relay.ranges.Load() != 1 {
			t.Fatal("preselected expectations changed saved history")
		}
		consumerFault.finish(t, 8, calls, 5)
	})
}

type advancingPersistenceFixture struct {
	bins                                   map[string]string
	python, reader, state, staging, backup string
	wrongExpectations                      string
	args                                   []string
	anchor                                 verify.GenesisTrustRoot
	opts                                   verify.VerifyOptions
	headers                                []chain.Header
	guards                                 []func()
	relay                                  *advancingPersistenceRelay
	last                                   map[string]any
}

func (f *advancingPersistenceFixture) check(t *testing.T, args []string, want int, exits [4]*int64) {
	t.Helper()
	result := runQueryCLI(t, f.bins["observe-block"], args...)
	var report struct {
		Version   int                    `json:"schema_version"`
		Status    string                 `json:"status"`
		Category  *string                `json:"category"`
		Count     int                    `json:"checked_targets"`
		Watch     *observerProcessRecord `json:"watch"`
		Collector *observerProcessRecord `json:"collector"`
		Verifier  *observerProcessRecord `json:"verifier"`
		Consumer  *observerProcessRecord `json:"consumer"`
	}
	if result.code != want || len(result.stderr) != 0 || json.Unmarshal(result.stdout, &report) != nil ||
		report.Version != 3 || len(losslessObject(t, result.stdout)) != 9 ||
		report.Watch == nil || report.Collector == nil || report.Verifier == nil || report.Consumer == nil {
		t.Fatalf("persistence observation metadata differs: actual=%d expected=%d summary=%s", result.code, want, result.stdout)
	}
	records := []*observerProcessRecord{report.Watch, report.Collector, report.Verifier, report.Consumer}
	for i, record := range records {
		if !reflect.DeepEqual(record.ExitCode, exits[i]) {
			t.Fatal("actual child completion differs from the selected failure boundary")
		}
	}
	if want == 0 {
		if report.Status != "matched" || report.Category != nil || report.Count != 5 {
			t.Fatal("completed persistence flow lost its complete batch")
		}
	} else if report.Status != "not_matched" || report.Category == nil || report.Count != 0 {
		t.Fatal("failed persistence flow acquired a target match")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, f.python, "-I", "-B", f.reader, "--mode", "advancing",
		"--observer-exit-code", strconv.Itoa(result.code), "--expected-targets", "5")
	cmd.Stdin = bytes.NewReader(result.stdout)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = &stdout, &stderr, time.Second
	err := cmd.Run()
	readerCode := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal("independent reader did not finish")
		}
		readerCode = exit.ExitCode()
	}
	text := "{\"schema_version\":1,\"status\":\"matched\",\"category\":null,\"checked_targets\":5}"
	if want != 0 {
		text = "{\"schema_version\":1,\"status\":\"not_matched\",\"category\":\"process_failure\",\"checked_targets\":0}"
	}
	expectedReaderCode := 0
	if want != 0 {
		expectedReaderCode = 2
	}
	if ctx.Err() != nil || readerCode != expectedReaderCode || stderr.Len() != 0 ||
		(stdout.String() != text+"\n" && stdout.String() != text+"\r\n") {
		t.Fatal("independent reader completion or fixed output differs")
	}
	for _, secret := range []string{"PRIVATE", f.state, f.staging, args[slices.Index(args, "--rpc")+1], args[slices.Index(args, "--expect-context")+1]} {
		if bytes.Contains(result.stdout, []byte(secret)) {
			t.Fatal("persistence summary disclosed private selections")
		}
	}
	f.last = map[string]any{"outer_exit": result.code, "reader_exit": readerCode,
		"watch_exit": report.Watch.ExitCode, "collector_exit": report.Collector.ExitCode,
		"verifier_exit": report.Verifier.ExitCode, "consumer_exit": report.Consumer.ExitCode,
		"checked_targets": report.Count}
}

func (f *advancingPersistenceFixture) finish(t *testing.T, tipIndex int, beforeCalls int64, wantCalls int) {
	t.Helper()
	select {
	case <-f.relay.failures:
		t.Fatal("owned RPC relay failed")
	default:
	}
	calls := int(f.relay.calls.Load() - beforeCalls)
	if calls != wantCalls {
		t.Fatal("watch or collection made an unselected request or retried")
	}
	state, err := verify.LoadTrustedState(f.state, f.anchor, f.opts)
	if err != nil || !reflect.DeepEqual(state.Snapshot().RetainedWindow, f.headers[:tipIndex+1]) {
		t.Fatal("complete reloaded state differs from the independently selected corpus prefix")
	}
	lock, err := statelock.Acquire(f.state)
	if err != nil || lock.Close() != nil {
		t.Fatal("completed watch retained writer ownership")
	}
	for _, guard := range f.guards {
		guard()
	}
	for _, path := range []string{f.staging, filepath.Dir(f.state)} {
		entries, err := os.ReadDir(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if path == f.staging || strings.HasPrefix(entry.Name(), ".spv-state-") {
				t.Fatal("completed workflow left private staging or save scratch")
			}
		}
	}
	f.last["case"] = strings.TrimPrefix(t.Name(), "TestCompiledAdvancingObserverPersistence/")
	f.last["saved_tip"] = f.headers[tipIndex].Height
	f.last["complete_saved_headers"] = tipIndex + 1
	f.last["peer_requests"] = calls
	f.last["private_staging_empty"] = true
	f.last["writer_lock_reacquired"] = true
	raw, err := json.Marshal(f.last)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("advancing-persistence-observation %s", raw)
}

type advancingPersistenceRelay struct {
	url                string
	calls, ranges      atomic.Int64
	afterRangeDone     atomic.Bool
	collectorFaultDone atomic.Bool
	failures           chan error
}

func newAdvancingPersistenceRelay(t *testing.T, target string, afterRange func() error, failCollector bool) *advancingPersistenceRelay {
	t.Helper()
	p := &advancingPersistenceRelay{failures: make(chan error, 4)}
	client := &http.Client{Timeout: 5 * time.Second}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		fail := func() {
			select {
			case p.failures <- errors.New("owned relay failure"):
			default:
			}
			w.WriteHeader(http.StatusBadGateway)
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 16385))
		if err != nil || len(raw) > 16384 || r.Method != http.MethodPost {
			fail()
			return
		}
		var request struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.Unmarshal(raw, &request) != nil {
			fail()
			return
		}
		var start, count uint64
		isRange := request.Method == "ledger.getMomentumsByHeight" && len(request.Params) == 2 &&
			json.Unmarshal(request.Params[0], &start) == nil && json.Unmarshal(request.Params[1], &count) == nil
		if failCollector && isRange && start == 4001 && count == 1 && p.collectorFaultDone.CompareAndSwap(false, true) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": map[string]any{"list": []any{}}})
			return
		}
		forward, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, bytes.NewReader(raw))
		if err != nil {
			fail()
			return
		}
		forward.Header.Set("Content-Type", "application/json")
		response, err := client.Do(forward)
		if err != nil {
			fail()
			return
		}
		defer func() { _ = response.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		if err != nil || response.StatusCode != http.StatusOK || len(body) > 1<<20 {
			fail()
			return
		}
		if isRange && start == 4007 && count == 3 {
			p.ranges.Add(1)
			if p.afterRangeDone.CompareAndSwap(false, true) && afterRange != nil {
				if afterRange() != nil {
					fail()
					return
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(body); err != nil {
			fail()
		}
	}))
	t.Cleanup(server.Close)
	p.url = server.URL
	return p
}
