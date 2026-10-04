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
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// All four ordinary commands run against the pinned node corpus and synthetic
// trust inputs. The one loopback operator is not independent network evidence.
func TestCompiledRPCBlockObserver(t *testing.T) {
	bins := buildQueryCLIs(t, "fetch-bundle", "zenon-spv", "consume-query-report", "observe-block")
	hashes := make(map[string]string)
	for name, path := range bins {
		digest := sha256.Sum256(readCLIFile(t, path))
		hashes[name] = hex.EncodeToString(digest[:])
	}
	c, bundle := contractBatchBundle(t)
	headers := bundle.Headers
	opts := verify.VerifyOptions{Policy: verify.DefaultPolicy()}
	opts.Policy.RetainHeaders = 16
	opts.Policy.ProtocolProfile = &verify.ProtocolProfile{Version: 1, Anchor: c.Chain.Anchor,
		ValidThrough: headers[len(headers)-1].Height, Source: "PRIVATE_RPC_OBSERVER_PROFILE"}
	var entries []verify.ProducerEntry
	for _, h := range headers {
		entries = append(entries, verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
	}
	schedule, err := verify.NewProducerSchedule(c.Chain.Anchor.ChainID,
		[]verify.ProducerCoverage{{FromHeight: headers[0].Height, ThroughHeight: headers[len(headers)-1].Height}}, entries, nil, nil)
	if err != nil {
		t.Fatal("cannot select synthetic producer coverage")
	}
	opts.ProducerAuth = verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired, Authorizer: verify.NewScheduleAuthorizer(schedule)}
	state, err := verify.NewVerifiedState(c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal("cannot initialize explicit synthetic settings")
	}
	accepted, state := state.Extend(headers)
	if accepted.Outcome != verify.OutcomeAccept {
		t.Fatal("selected node corpus headers refused")
	}
	selectedContext, err := state.VerificationContext()
	if err != nil || selectedContext.Fingerprint == nil {
		t.Fatal("missing independently selected context")
	}
	pin := hex.EncodeToString(selectedContext.Fingerprint[:])
	dir := t.TempDir()
	anchorPath := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", c.Chain.Anchor)
	profilePath := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", opts.Policy.ProtocolProfile)
	schedulePath := writeCLIJSON(t, dir, "PRIVATE_SCHEDULE.json", schedule)
	statePath := filepath.Join(dir, "PRIVATE_STATE.json")
	if state.Save(statePath) != nil {
		t.Fatal("cannot save selected state")
	}
	private := filepath.Join(dir, "PRIVATE_RECORDS")
	if os.Mkdir(private, 0o700) != nil {
		t.Fatal("cannot create protected run parent")
	}
	var guards []func()
	for _, path := range []string{anchorPath, profilePath, schedulePath, statePath} {
		guards = append(guards, protectCLIState(t, path))
	}
	peer := newQueryCLIPeer(t, c, false)
	for _, command := range []string{"verify-commitment", "verify-segment"} {
		t.Run(command, func(t *testing.T) {
			refs := []any{}
			for i, evidence := range bundle.Commitments {
				ref := map[string]any{"scope": "commitment", "index": i, "momentum_height": evidence.Height, "account_header": evidence.Target}
				if command == "verify-segment" {
					ref = map[string]any{"scope": "segment", "index": 0, "block_index": i, "account_header": evidence.Target}
				}
				refs = append(refs, ref)
			}
			expected := map[string]any{"schema_version": 1, "command": command, "context_fingerprint": pin,
				"verification_tip": map[string]any{"hash": headers[len(headers)-1].HeaderHash, "height": headers[len(headers)-1].Height},
				"targets":          refs, "required_guarantees": []string{"CONTENT_INCLUSION"},
				"allowed_trust_assumptions": []string{"TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_RETAINED_WINDOW_DEPTH", "TRUST_EXTERNAL_PROTOCOL_PROFILE", "TRUST_EXTERNAL_PRODUCER_SCHEDULE"}}
			expectedPath := writeCLIJSON(t, dir, "PRIVATE_"+command+"_EXPECTATIONS.json", expected)
			guardExpected := protectCLIState(t, expectedPath)
			args := []string{"--collector", bins["fetch-bundle"], "--collector-sha256", hashes["fetch-bundle"],
				"--rpc", peer.url, "--height", "4009", "--count", "8",
				"--verifier", bins["zenon-spv"], "--verifier-sha256", hashes["zenon-spv"],
				"--consumer", bins["consume-query-report"], "--consumer-sha256", hashes["consume-query-report"],
				"--command", command, "--genesis-config", anchorPath, "--protocol-profile", profilePath, "--schedule", schedulePath,
				"--state", statePath, "--expectations", expectedPath, "--private-dir", private,
				"--expect-context", pin, "--window", "low", "--retain-headers", "16"}
			if command == "verify-segment" {
				args = append(args, "--segments", c.Segments[0].RPCAddress+":1-5")
			} else {
				args = append(args, "--commitments", c.Segments[0].RPCAddress)
			}
			set := func(option, value string) []string {
				changed := slices.Clone(args)
				changed[slices.Index(changed, option)+1] = value
				return changed
			}
			check := func(t *testing.T, selected []string, want int, category string, count int, collectorCompleted, verifierCompleted, consumerCompleted, mainRequests bool, extraEnvironment ...string) {
				t.Helper()
				before := peer.calls.Load()
				var result queryCLIResult
				if len(extraEnvironment) == 0 {
					result = runQueryCLI(t, bins["observe-block"], selected...)
				} else {
					// Run once with deliberately hostile inherited defaults. The
					// ordinary helper otherwise strips ZENON_SPV_* settings.
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					process := exec.CommandContext(ctx, bins["observe-block"], selected...)
					process.Env = append(queryCLIEnvironment(), extraEnvironment...)
					var out, diagnostics bytes.Buffer
					process.Stdout, process.Stderr = &out, &diagnostics
					err := process.Run()
					result = queryCLIResult{stdout: out.Bytes(), stderr: diagnostics.Bytes()}
					var failed *exec.ExitError
					if errors.As(err, &failed) {
						result.code = failed.ExitCode()
					} else if err != nil {
						t.Fatal("cannot run environment selection case")
					}
				}
				var report struct {
					Version   int                    `json:"schema_version"`
					Status    string                 `json:"status"`
					Category  *string                `json:"category"`
					Count     int                    `json:"checked_targets"`
					ElapsedNS int64                  `json:"elapsed_ns"`
					Collector *observerProcessRecord `json:"collector"`
					Verifier  observerProcessRecord  `json:"verifier"`
					Consumer  observerProcessRecord  `json:"consumer"`
				}
				// A fast setup refusal can finish within one Windows clock tick.
				// Actual child status, not positive elapsed time, proves completion.
				if result.code != want || len(result.stderr) != 0 || json.Unmarshal(result.stdout, &report) != nil ||
					report.Version != 2 || report.Collector == nil || report.Count != count || report.ElapsedNS < 0 ||
					(report.Category == nil) != (want == 0) || (report.Collector.ExitCode != nil) != collectorCompleted ||
					(report.Verifier.ExitCode != nil) != verifierCompleted || (report.Consumer.ExitCode != nil) != consumerCompleted ||
					len(losslessObject(t, result.stdout)) != 8 {
					t.Fatalf("RPC observer summary disagreed with actual completion: exit=%d schema=%d targets=%d elapsed_ns=%d stderr_bytes=%d", result.code, report.Version, report.Count, report.ElapsedNS, len(result.stderr))
				}
				if want == 0 {
					if report.Status != "matched" || *report.Collector.ExitCode != 0 || *report.Verifier.ExitCode != 0 || *report.Consumer.ExitCode != 0 || report.Collector.StdoutBytes <= 0 {
						t.Fatal("matched result lacked successful collection/verification/consumption")
					}
				} else if report.Status != "not_matched" || *report.Category != category {
					t.Fatal("RPC observation lost its fixed refusal category")
				}
				if (peer.calls.Load() > before) != mainRequests {
					t.Fatal("collection made unexpected selected-peer requests")
				}
				for _, secret := range []string{"PRIVATE", dir, peer.url, pin, c.Segments[0].RPCAddress, hashes["fetch-bundle"], hashes["zenon-spv"], hashes["consume-query-report"]} {
					if bytes.Contains(result.stdout, []byte(secret)) {
						t.Fatal("RPC observer reproduced private inputs or diagnostics")
					}
				}
				for _, guard := range guards {
					guard()
				}
				guardExpected()
				files, err := os.ReadDir(private)
				if err != nil || len(files) != 0 {
					t.Fatal("RPC observer left raw private files")
				}
				if _, err := os.Stat(statePath + ".lock"); !os.IsNotExist(err) {
					t.Fatal("read-only RPC observation acquired writer ownership")
				}
			}
			t.Run("matched", func(t *testing.T) { check(t, args, 0, "", len(refs), true, true, true, true) })
			for _, option := range []string{"--collector-sha256", "--verifier-sha256", "--consumer-sha256"} {
				t.Run("wrong "+option, func(t *testing.T) {
					check(t, set(option, strings.Repeat("0", 64)), 2, "binary_mismatch", 0, false, false, false, false)
				})
			}
			t.Run("missing local state makes no RPC", func(t *testing.T) {
				check(t, set("--state", filepath.Join(dir, "PRIVATE_ABSENT")), 70, "input_unavailable", 0, false, false, false, false)
			})
			t.Run("context drift", func(t *testing.T) {
				check(t, set("--expect-context", strings.Repeat("1", 64)), 2, "process_failure", 0, true, true, false, true)
			})
			t.Run("wrong selected target", func(t *testing.T) {
				e := losslessObject(t, marshalCLIValue(t, expected))
				e["targets"].([]any)[0].(map[string]any)["account_header"].(map[string]any)["hash"] = strings.Repeat("2", 64)
				path := writeCLIJSON(t, dir, "PRIVATE_"+command+"_WRONG_TARGET.json", e)
				defer protectCLIState(t, path)()
				check(t, set("--expectations", path), 2, "target_mismatch", 0, true, true, true, true)
			})
			t.Run("collector start failure", func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "PRIVATE_NOT_EXECUTABLE")
				if os.WriteFile(path, []byte("PRIVATE_INVALID_EXECUTABLE"), 0o600) != nil {
					t.Fatal("cannot prepare failed start")
				}
				h := sha256.Sum256(readCLIFile(t, path))
				changed := set("--collector", path)
				changed[slices.Index(changed, "--collector-sha256")+1] = hex.EncodeToString(h[:])
				check(t, changed, 70, "process_unavailable", 0, false, false, false, false)
			})
			t.Run("failed collection stops before verification", func(t *testing.T) {
				peer.rangeFault.Store(7)
				defer peer.rangeFault.Store(0)
				check(t, args, 2, "process_failure", 0, true, false, false, true)
			})
			t.Run("collection deadline", func(t *testing.T) {
				var requests atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					requests.Add(1)
					<-r.Context().Done()
				}))
				defer server.Close()
				changed := append(set("--rpc", server.URL), "--timeout", "750ms")
				check(t, changed, 2, "timeout", 0, true, false, false, false)
				if requests.Load() != 1 {
					t.Fatal("deadline retried or never requested the selected endpoint")
				}
			})
			t.Run("explicit RPC excludes inherited endpoints", func(t *testing.T) {
				var calls atomic.Int64
				unselected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				defer unselected.Close()
				check(t, args, 0, "", len(refs), true, true, true, true, "ZENON_SPV_RPC="+unselected.URL, "ZENON_SPV_PEERS="+unselected.URL)
				if calls.Load() != 0 {
					t.Fatal("RPC collection contacted an unselected inherited endpoint")
				}
			})
			t.Run("recovery preserves original selection", func(t *testing.T) { check(t, args, 0, "", len(refs), true, true, true, true) })
		})
	}
}
