package conformance_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Refused redirects must not publish candidates, advance state, count an
// unselected endpoint toward quorum, or disclose its Location in reports.
func TestCompiledRPCRedirectBoundary(t *testing.T) {
	bins := buildQueryCLIs(t, "zenon-spv", "fetch-bundle")
	c, bundle := contractBatchBundle(t)
	dir := t.TempDir()
	anchor := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", c.Chain.Anchor)
	profile := verify.ProtocolProfile{Version: 1, Anchor: c.Chain.Anchor, ValidThrough: 4010, Source: "PRIVATE_PROFILE_SOURCE"}
	profilePath := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", profile)
	var entries []verify.ProducerEntry
	for _, h := range bundle.Headers {
		entries = append(entries, verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix,
			ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
	}
	schedule, err := verify.NewProducerSchedule(c.Chain.Anchor.ChainID,
		[]verify.ProducerCoverage{{FromHeight: 4001, ThroughHeight: 4009}}, entries,
		[]string{"PRIVATE_SCHEDULE_PEER"}, map[string]uint64{"PRIVATE_SCHEDULE_PEER": 4009})
	if err != nil {
		t.Fatal(err)
	}
	schedulePath := writeCLIJSON(t, dir, "PRIVATE_SCHEDULE.json", schedule)
	policy := verify.DefaultPolicy()
	policy.ProtocolProfile = &profile
	state, err := verify.NewVerifiedState(c.Chain.Anchor, verify.VerifyOptions{Policy: policy,
		ProducerAuth: verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired, Authorizer: verify.NewScheduleAuthorizer(schedule)}})
	if err != nil {
		t.Fatal(err)
	}
	accepted, state := state.Extend(bundle.Headers)
	if accepted.Outcome != verify.OutcomeAccept {
		t.Fatal("fixture state did not accept its explicitly selected trust inputs")
	}
	statePath := filepath.Join(dir, "PRIVATE_STATE.json")
	if err := state.Save(statePath); err != nil {
		t.Fatal(err)
	}
	checkState := protectCLIState(t, statePath)
	raw, err := state.VerificationContextJSON()
	var context verify.VerificationContext
	if err != nil || json.Unmarshal(raw, &context) != nil || context.Fingerprint == nil {
		t.Fatal("fixture state did not retain its trust context")
	}
	common := []string{"--json", "--state", statePath, "--genesis-config", anchor, "--protocol-profile", profilePath,
		"--schedule", schedulePath, "--expect-context", hex.EncodeToString(context.Fingerprint[:])}
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, multi := range []bool{false, true} {
			for _, command := range []string{"fetch-bundle", "watch"} {
				t.Run(fmt.Sprintf("status=%d/multi=%t/command=%s", status, multi, command), func(t *testing.T) {
					caseDir := t.TempDir()
					var destinationCalls atomic.Int32
					// A valid selected destination would otherwise supply a signed
					// corpus target and range; all redirect peers point to this one
					// service. It is not an independent peer set or a network pilot.
					good := newQueryCLIPeer(t, c, false, bundle.Headers[8])
					destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						destinationCalls.Add(1)
						w.Header().Set("Location", good.url)
						w.WriteHeader(http.StatusTemporaryRedirect)
					}))
					t.Cleanup(destination.Close)
					var peerCalls atomic.Int32
					newPeer := func() string {
						peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
							peerCalls.Add(1)
							w.Header().Set("Location", destination.URL+"/PRIVATE_LOCATION?token=PRIVATE_REDIRECT_SECRET")
							w.WriteHeader(status)
							_, _ = io.WriteString(w, "PRIVATE_REDIRECT_BODY")
						}))
						t.Cleanup(peer.Close)
						return strings.Replace(peer.URL, "://", "://PRIVATE_USER:PRIVATE_PASSWORD@", 1) + "/PRIVATE_PATH?token=PRIVATE_SELECTED_SECRET"
					}
					selection := []string{"--rpc", newPeer()}
					wantCalls := int32(1)
					if multi {
						selection = []string{"--peers", selection[1] + "," + newPeer(), "--quorum", "2"}
						wantCalls = 2
					}
					if command == "fetch-bundle" {
						candidate := writeCLIJSON(t, caseDir, "PRIVATE_CANDIDATE.json", map[string]bool{"existing": true})
						checkpoint := writeCLIJSON(t, caseDir, "PRIVATE_CHECKPOINT.json", map[string]bool{"existing": true})
						checkCandidate, checkCheckpoint := protectCLIState(t, candidate), protectCLIState(t, checkpoint)
						args := append(slices.Clone(selection), "--height", "4009", "--count", "8", "--out", candidate, "--checkpoint", checkpoint)
						result := runQueryCLI(t, bins[command], args...)
						if result.code != 1 || len(result.stdout) != 0 || !bytes.Contains(result.stderr, []byte(fmt.Sprintf("rpc http %d", status))) {
							t.Fatal("redirect collection published evidence or lost its safe HTTP failure")
						}
						assertOperatorPrivacy(t, result, dir)
						assertOperatorPrivacy(t, result, caseDir)
						checkCandidate()
						checkCheckpoint()
					} else {
						args := append([]string{"watch"}, common...)
						args = append(args, selection...)
						args = append(args, "--once", "--safety-margin", "1", "--batch-size", "1")
						result := runQueryCLI(t, bins["zenon-spv"], args...)
						decoder := json.NewDecoder(bytes.NewReader(result.stdout))
						var started, tick cliWatchEvent
						if result.code != 2 || len(result.stderr) != 0 || decoder.Decode(&started) != nil || decoder.Decode(&tick) != nil || decoder.Decode(new(any)) != io.EOF ||
							started.Event != "started" || tick.Event != "refused" || tick.Persistence != "not_attempted" || tick.Verification != nil ||
							tick.Error == nil || tick.Error.Stage != "frontier" || tick.Error.Category != "quorum_unavailable" || tick.FetchedCount != 0 || tick.CandidateTip != nil ||
							tick.StateTip.Height != 4009 || tick.StateTip.Hash != bundle.Headers[8].HeaderHash || tick.Context.Fingerprint == nil || *tick.Context.Fingerprint != *context.Fingerprint {
							t.Fatal("redirect watch advanced state or lost its pinned, non-verification refusal")
						}
						assertOperatorPrivacy(t, result, dir)
					}
					if peerCalls.Load() != wantCalls || destinationCalls.Load() != 0 || good.calls.Load() != 0 {
						t.Fatal("redirect followed an unselected destination or reused it for quorum")
					}
					checkState()
				})
			}
		}
	}
}
