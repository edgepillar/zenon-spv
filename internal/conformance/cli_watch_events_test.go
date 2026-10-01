package conformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/statelock"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Decode the executable's stream independently of syncer's event structures.
type cliWatchEvent struct {
	SchemaVersion           uint32                            `json:"schema_version"`
	Command                 string                            `json:"command"`
	Event                   string                            `json:"event"`
	StateTip                chain.HashHeight                  `json:"state_tip"`
	PreviousTipHeight       *uint64                           `json:"previous_tip_height"`
	CandidateTip            *chain.HashHeight                 `json:"candidate_tip"`
	TargetHeight            *uint64                           `json:"target_height"`
	FetchedCount            int                               `json:"fetched_count"`
	Reason                  *string                           `json:"reason"`
	Persistence             string                            `json:"persistence"`
	ConsecutiveSaveFailures int                               `json:"consecutive_save_failures"`
	Error                   *struct{ Stage, Category string } `json:"error"`
	Verification            *struct {
		Outcome, Reason  string
		FailedAt         int                      `json:"failed_at"`
		Proven           []verify.Guarantee       `json:"proven"`
		NotProven        []verify.Guarantee       `json:"not_proven"`
		TrustAssumptions []verify.TrustAssumption `json:"trust_assumptions"`
	} `json:"verification"`
	Context     verify.VerificationContext `json:"verification_context"`
	StateTrust  []verify.TrustAssumption   `json:"state_trust"`
	SourceTrust []verify.TrustAssumption   `json:"source_trust"`
	Settings    json.RawMessage            `json:"settings"`
	Caveats     []string                   `json:"caveats"`
}

type watchEventStream struct {
	buffer bytes.Buffer
	once   sync.Once
	ticked chan struct{}
}

func (s *watchEventStream) Write(p []byte) (int, error) {
	n, err := s.buffer.Write(p)
	if bytes.Count(s.buffer.Bytes(), []byte{'\n'}) >= 2 {
		s.once.Do(func() { close(s.ticked) })
	}
	return n, err
}

func TestCompiledWatchJSONEvents(t *testing.T) {
	testCompiledWatchJSONEvents(t, false)
}

func TestCompiledWatchOnceJSONEvents(t *testing.T) {
	testCompiledWatchJSONEvents(t, true)
}

func testCompiledWatchJSONEvents(t *testing.T, once bool) {
	t.Helper()
	binary := buildQueryCLIs(t, "zenon-spv")["zenon-spv"]
	for _, mode := range []string{"advanced", "caught_up", "rejected", "profile_refused", "frontier_refused",
		"retained_hash_refused", "retained_key_refused", "retained_signature_refused"} {
		t.Run(mode, func(t *testing.T) {
			c, headers, policy := transitionFixture(t)
			policy.W = 5 // Seed five headers; the CLI raises the depth to six.
			policy.ProtocolProfile.Source = "PRIVATE_PROFILE_SOURCE"
			if mode == "profile_refused" {
				policy.ProtocolProfile.ValidThrough = 2005
			}
			entries := make([]verify.ProducerEntry, len(headers))
			for i, h := range headers {
				entries[i] = verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix,
					ProducingAddr: chain.PubKeyToAddress(h.PublicKey)}
			}
			schedule, err := verify.NewProducerSchedule(c.Transition.Anchor.ChainID,
				[]verify.ProducerCoverage{{FromHeight: 2001, ThroughHeight: 2006}}, entries,
				[]string{"PRIVATE_SCHEDULE_PEER"}, map[string]uint64{"PRIVATE_SCHEDULE_PEER": 2006})
			if err != nil {
				t.Fatal(err)
			}
			opts := verify.VerifyOptions{Policy: policy, ProducerAuth: verify.ProducerAuthOptions{
				Mode: verify.ProducerAuthRequired, Authorizer: verify.NewScheduleAuthorizer(schedule)}}
			state, err := verify.NewVerifiedState(c.Transition.Anchor, opts)
			if err != nil {
				t.Fatal(err)
			}
			result, state := state.Extend(headers[:5])
			if result.Outcome != verify.OutcomeAccept {
				t.Fatal(result)
			}
			dir := t.TempDir()
			statePath := filepath.Join(dir, "PRIVATE_STATE.json")
			if err := state.Save(statePath); err != nil {
				t.Fatal(err)
			}
			before := readCLIFile(t, statePath)
			anchor := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", c.Transition.Anchor)
			profile := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", policy.ProtocolProfile)
			schedulePath := writeCLIJSON(t, dir, "PRIVATE_SCHEDULE.json", schedule)
			peer := startWatchJSONPeer(t, c.Transition.Vectors, headers, mode)
			endpoint := strings.Replace(peer, "://", "://PRIVATE_RPC_USER:PRIVATE_RPC_PASSWORD@", 1) + "/PRIVATE_RPC_PATH?token=PRIVATE_RPC_TOKEN"
			args := []string{"watch", "--json", "--rpc", endpoint, "--state", statePath, "--genesis-config", anchor,
				"--protocol-profile", profile, "--schedule", schedulePath, "--safety-margin", "1", "--batch-size", "3", "--interval", "1h", "--show-context"}
			if once {
				args = append(args, "--once")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			watch := exec.CommandContext(ctx, binary, args...)
			stream, diagnostics := &watchEventStream{ticked: make(chan struct{})}, &bytes.Buffer{}
			watch.Env, watch.Stdout, watch.Stderr = queryCLIEnvironment(), stream, diagnostics
			var unwantedRequests atomic.Int64
			if mode == "advanced" {
				unwanted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					unwantedRequests.Add(1)
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				t.Cleanup(unwanted.Close)
				watch.Env = append(watch.Env, "ZENON_SPV_PEERS="+unwanted.URL+"/PRIVATE_ENV_PEER")
			}
			watch.WaitDelay = time.Second
			if err := watch.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = watch.Process.Kill(); _ = watch.Wait() })
			if !once {
				select {
				case <-stream.ticked:
				case <-ctx.Done():
					t.Fatal("watch did not emit startup and a complete tick")
				}
				if runtime.GOOS == "windows" {
					err = watch.Process.Kill()
				} else {
					err = watch.Process.Signal(os.Interrupt)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			err = watch.Wait()
			if !once && runtime.GOOS != "windows" && err != nil || ctx.Err() != nil {
				t.Fatalf("watch did not stop cleanly: %v", err)
			}
			if once {
				wantExit := 0
				if mode == "rejected" {
					wantExit = 1
				} else if strings.HasSuffix(mode, "refused") {
					wantExit = 2
				}
				if watch.ProcessState.ExitCode() != wantExit {
					t.Fatalf("single-step exit=%d, want %d", watch.ProcessState.ExitCode(), wantExit)
				}
			}
			if diagnostics.Len() != 0 || bytes.Contains(stream.buffer.Bytes(), []byte("PRIVATE")) || bytes.Contains(stream.buffer.Bytes(), []byte(dir)) || bytes.Contains(stream.buffer.Bytes(), []byte(peer)) {
				t.Fatal("JSON watch mixed text diagnostics or disclosed private input")
			}
			if unwantedRequests.Load() != 0 {
				t.Fatal("explicit RPC selection contacted an environment peer")
			}
			lines := bytes.Split(bytes.TrimSuffix(stream.buffer.Bytes(), []byte{'\n'}), []byte{'\n'})
			if len(lines) != 2 {
				t.Fatal("watch emitted extra text or a partial event")
			}
			var events [2]cliWatchEvent
			for i, line := range lines {
				d := json.NewDecoder(bytes.NewReader(line))
				d.DisallowUnknownFields()
				if err := d.Decode(&events[i]); err != nil {
					t.Fatal(err)
				}
				e := events[i]
				if e.SchemaVersion != 1 || e.Command != "watch" || e.Context.ProtocolProfile == nil || e.Context.Producer.Kind != "schedule" ||
					!slices.Contains(e.StateTrust, verify.TrustExternalProtocolProfile) || !slices.Contains(e.StateTrust, verify.TrustExternalProducerSchedule) ||
					!slices.Equal(e.SourceTrust, []verify.TrustAssumption{verify.TrustRPCQuorum}) || len(e.Caveats) == 0 {
					t.Fatal("executable omitted the captured context or external trust")
				}
			}
			started, tick := events[0], events[1]
			if started.Event != "started" || started.StateTip.Hash != headers[4].HeaderHash || started.Verification != nil {
				t.Fatal("startup did not identify the trusted resume point")
			}
			if once {
				var settings struct {
					MaxStateSaveFailures int `json:"max_state_save_failures"`
				}
				if err := json.Unmarshal(started.Settings, &settings); err != nil || settings.MaxStateSaveFailures != 1 {
					t.Fatal("single-step startup advertised repeated save attempts")
				}
			}
			wantEvent, wantTip := mode, headers[4]
			if strings.HasSuffix(mode, "refused") {
				wantEvent = "refused"
			}
			switch mode {
			case "advanced":
				wantTip = headers[5]
				if tick.Verification == nil || tick.Verification.Outcome != "ACCEPT" || tick.Persistence != "saved" ||
					!slices.Contains(tick.Verification.Proven, verify.GuaranteeProducerAuthorization) ||
					slices.Contains(tick.Verification.Proven, verify.GuaranteeCanonicality) {
					t.Fatal("v2 advancement lost bounded verification guarantees")
				}
			case "caught_up":
				if tick.Verification != nil || tick.Persistence != "saved" || tick.CandidateTip != nil {
					t.Fatal("caught-up event invented new verification")
				}
			default:
				if tick.Persistence != "not_attempted" || !bytes.Equal(before, readCLIFile(t, statePath)) {
					t.Fatal("failed evidence changed persisted state")
				}
				if mode == "profile_refused" && (tick.Verification == nil || tick.Verification.Reason != "ReasonProtocolProfileCoverage") {
					t.Fatal("profile refusal lost its actual verification result")
				}
				if strings.HasPrefix(mode, "retained_") && (tick.Verification != nil || tick.CandidateTip != nil ||
					tick.Reason == nil || *tick.Reason != "ReasonRetainedHeaderMismatch" || tick.Error == nil ||
					tick.Error.Stage != "retained_target" || tick.Error.Category != "header_mismatch") {
					t.Fatal("conflicting target claimed verification or lost its refusal category")
				}
			}
			if tick.Event != wantEvent || tick.StateTip.Height != wantTip.Height || tick.StateTip.Hash != wantTip.HeaderHash {
				t.Fatal("watch event differs from the independently pinned tip")
			}
			resumed, err := verify.LoadTrustedState(statePath, c.Transition.Anchor, opts)
			if tip, _ := resumed.Tip(); err != nil || tip.HeaderHash != wantTip.HeaderHash || tip.NextWorkPrice != wantTip.NextWorkPrice {
				t.Fatal("JSON watch did not preserve trusted resume and v2 fields")
			}
			lock, err := statelock.Acquire(statePath)
			if err != nil {
				t.Fatal("stopped watch retained writer ownership")
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The frontier is a synthetic height hint, one above the pinned corpus. The
// actual target and verification response remain the node-produced v2 header.
func startWatchJSONPeer(t *testing.T, vectors []momentumVector, headers []chain.Header, mode string) string {
	t.Helper()
	var frontier map[string]json.RawMessage
	if err := json.Unmarshal(vectors[5].Momentum, &frontier); err != nil {
		t.Fatal(err)
	}
	hint := headers[5]
	hint.Height++
	hint.PreviousHash = hint.HeaderHash
	hint.TimestampUnix += 10
	hint.HeaderHash = hint.ComputeHash()
	for name, value := range map[string]any{"height": hint.Height, "previousHash": hint.PreviousHash, "timestamp": hint.TimestampUnix, "hash": hint.HeaderHash} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		frontier[name] = raw
	}
	block := vectors[5].Momentum
	retainedTarget := mode == "caught_up" || strings.HasPrefix(mode, "retained_")
	if retainedTarget {
		block = vectors[4].Momentum
	}
	if strings.HasPrefix(mode, "retained_") {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(block, &fields); err != nil {
			t.Fatal(err)
		}
		h := headers[4]
		switch mode {
		case "retained_hash_refused":
			h.TimestampUnix++
			h.HeaderHash = h.ComputeHash()
			fields["timestamp"], _ = json.Marshal(h.TimestampUnix)
			fields["hash"], _ = json.Marshal(h.HeaderHash)
		case "retained_key_refused":
			h.PublicKey = slices.Clone(h.PublicKey)
			h.PublicKey[0] ^= 1
			fields["publicKey"], _ = json.Marshal(h.PublicKey)
		case "retained_signature_refused":
			h.Signature = slices.Clone(h.Signature)
			h.Signature[0] ^= 1
			fields["signature"], _ = json.Marshal(h.Signature)
		}
		block, _ = json.Marshal(fields)
	}
	if mode == "rejected" {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(block, &fields); err != nil {
			t.Fatal(err)
		}
		signature := slices.Clone(headers[5].Signature)
		signature[0] ^= 1
		fields["signature"], _ = json.Marshal(signature)
		block, _ = json.Marshal(fields)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage
			Method string
			Params []uint64
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		var result any
		switch req.Method {
		case "ledger.getFrontierMomentum":
			result = frontier
			if retainedTarget {
				result = vectors[5].Momentum
			} else if mode == "frontier_refused" {
				result = privateRPCConversionValue(t, vectors[5].Momentum, "content")
			}
		case "ledger.getMomentumsByHeight":
			expected := uint64(2006)
			if retainedTarget {
				expected--
			}
			if !slices.Equal(req.Params, []uint64{expected, 1}) {
				t.Error("unexpected watch range")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			result = map[string]any{"list": []json.RawMessage{block}}
		default:
			t.Error("unexpected watch method")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}
