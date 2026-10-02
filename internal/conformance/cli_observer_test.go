package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type observerProcessRecord struct {
	ExitCode    *int64 `json:"exit_code"`
	ElapsedNS   int64  `json:"elapsed_ns"`
	StdoutBytes int64  `json:"stdout_bytes"`
	StderrBytes int64  `json:"stderr_bytes"`
}

// This is the selected observer application's local integration, using node
// corpus identities and explicit synthetic attestations. It runs no public RPC
// and does not authenticate network inputs, report provenance or finality.
func TestCompiledBlockObserver(t *testing.T) {
	bins := buildQueryCLIs(t, "zenon-spv", "consume-query-report", "observe-block")
	binaryHash := func(name string) string {
		raw, err := os.ReadFile(bins[name])
		if err != nil {
			t.Fatal("cannot identify selected binary")
		}
		h := sha256.Sum256(raw)
		return hex.EncodeToString(h[:])
	}
	verifierHash, consumerHash := binaryHash("zenon-spv"), binaryHash("consume-query-report")
	for _, command := range []string{"verify-commitment", "verify-segment"} {
		t.Run(command, func(t *testing.T) {
			var anchor verify.GenesisTrustRoot
			var headers []chain.Header
			var bundle proof.HeaderBundle
			var opts verify.VerifyOptions
			var schedule *verify.ProducerSchedule
			if command == "verify-commitment" {
				w := newFlatWorkload(t, 1000, 16)
				anchor, headers, bundle, opts, schedule = w.corpus.Anchor, w.sample.Headers, w.bundle, w.opts, w.schedule
			} else {
				c, b := contractBatchBundle(t)
				anchor, headers, bundle = c.Chain.Anchor, b.Headers, b
				bundle.Headers = nil
				opts.Policy = verify.DefaultPolicy()
				opts.Policy.ProtocolProfile = &verify.ProtocolProfile{Version: 1, Anchor: anchor, ValidThrough: headers[len(headers)-1].Height, Source: "PRIVATE_OBSERVER_PROFILE"}
				var entries []verify.ProducerEntry
				for _, h := range headers {
					entries = append(entries, verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
				}
				var err error
				schedule, err = verify.NewProducerSchedule(anchor.ChainID, []verify.ProducerCoverage{{FromHeight: headers[0].Height, ThroughHeight: headers[len(headers)-1].Height}}, entries, nil, nil)
				if err != nil {
					t.Fatal("cannot select synthetic producer coverage")
				}
				opts.ProducerAuth = verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired, Authorizer: verify.NewScheduleAuthorizer(schedule)}
			}
			opts.Policy.RetainHeaders = 16
			state, err := verify.NewVerifiedState(anchor, opts)
			if err != nil {
				t.Fatal("cannot initialize explicit synthetic settings")
			}
			accepted, state := state.Extend(headers)
			if accepted.Outcome != verify.OutcomeAccept {
				t.Fatal("selected node corpus headers refused")
			}
			context, err := state.VerificationContext()
			if err != nil || context.Fingerprint == nil {
				t.Fatal("missing explicitly selected context pin")
			}
			pin := hex.EncodeToString(context.Fingerprint[:])
			dir := t.TempDir()
			anchorPath := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", anchor)
			profilePath := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", opts.Policy.ProtocolProfile)
			schedulePath := writeCLIJSON(t, dir, "PRIVATE_SCHEDULE.json", schedule)
			bundlePath := writeCLIJSON(t, dir, "PRIVATE_BUNDLE.json", bundle)
			statePath := filepath.Join(dir, "PRIVATE_STATE.json")
			if state.Save(statePath) != nil {
				t.Fatal("cannot save selected test state")
			}
			refs := []any{}
			for i, evidence := range bundle.Commitments {
				ref := map[string]any{"scope": "commitment", "index": i, "momentum_height": evidence.Height, "account_header": evidence.Target}
				if command == "verify-segment" {
					ref = map[string]any{"scope": "segment", "index": 0, "block_index": i, "account_header": evidence.Target}
				}
				refs = append(refs, ref)
			}
			expected := map[string]any{"schema_version": 1, "command": command, "context_fingerprint": pin,
				"verification_tip": map[string]any{"hash": headers[len(headers)-1].HeaderHash, "height": headers[len(headers)-1].Height}, "targets": refs,
				"required_guarantees":       []string{"CONTENT_INCLUSION"},
				"allowed_trust_assumptions": []string{"TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_RETAINED_WINDOW_DEPTH", "TRUST_EXTERNAL_PROTOCOL_PROFILE", "TRUST_EXTERNAL_PRODUCER_SCHEDULE"}}
			expectedPath := writeCLIJSON(t, dir, "PRIVATE_EXPECTATIONS.json", expected)
			private := filepath.Join(dir, "private-records")
			if os.Mkdir(private, 0o700) != nil {
				t.Fatal("cannot create private run directory")
			}
			args := []string{"--verifier", bins["zenon-spv"], "--verifier-sha256", verifierHash, "--consumer", bins["consume-query-report"], "--consumer-sha256", consumerHash,
				"--command", command, "--genesis-config", anchorPath, "--protocol-profile", profilePath, "--schedule", schedulePath,
				"--state", statePath, "--bundle", bundlePath, "--expectations", expectedPath, "--private-dir", private,
				"--expect-context", pin, "--window", "low", "--retain-headers", "16"}
			var guards []func()
			for _, path := range []string{anchorPath, profilePath, schedulePath, statePath, bundlePath, expectedPath} {
				guards = append(guards, protectCLIState(t, path))
			}
			check := func(t *testing.T, selected []string, want int, category string, count int, verifierStarted, consumerStarted bool) {
				t.Helper()
				result := runQueryCLI(t, bins["observe-block"], selected...)
				var report struct {
					Version   int                   `json:"schema_version"`
					Status    string                `json:"status"`
					Category  *string               `json:"category"`
					Count     int                   `json:"checked_targets"`
					ElapsedNS int64                 `json:"elapsed_ns"`
					Verifier  observerProcessRecord `json:"verifier"`
					Consumer  observerProcessRecord `json:"consumer"`
				}
				if result.code != want || len(result.stderr) != 0 || json.Unmarshal(result.stdout, &report) != nil || report.Version != 1 || report.Count != count ||
					report.ElapsedNS <= 0 || (report.Category == nil) != (want == 0) || (report.Verifier.ExitCode != nil) != verifierStarted || (report.Consumer.ExitCode != nil) != consumerStarted {
					t.Fatal("observer summary disagreed with actual completion")
				}
				if want == 0 {
					if report.Status != "matched" || *report.Verifier.ExitCode != 0 || *report.Consumer.ExitCode != 0 {
						t.Fatal("matched summary lacked successful child completion")
					}
				} else if report.Status != "not_matched" || *report.Category != category {
					t.Fatal("refusal lost its fixed category")
				}
				if len(losslessObject(t, result.stdout)) != 7 {
					t.Fatal("observer summary acquired unintended fields")
				}
				for _, child := range []observerProcessRecord{report.Verifier, report.Consumer} {
					if child.ExitCode != nil && (child.ElapsedNS <= 0 || child.StdoutBytes <= 0 || child.StderrBytes < 0) {
						t.Fatal("completed child lost its resource observations")
					}
				}
				for _, secret := range []string{"PRIVATE", dir, pin, verifierHash, consumerHash, hex.EncodeToString(bundle.Commitments[0].Target.Hash[:])} {
					if bytes.Contains(result.stdout, []byte(secret)) {
						t.Fatal("observer reproduced private inputs or diagnostics")
					}
				}
				for _, guard := range guards {
					guard()
				}
				entries, err := os.ReadDir(private)
				if err != nil || len(entries) != 0 {
					t.Fatal("observer left raw private run files behind")
				}
				if _, err := os.Stat(statePath + ".lock"); !os.IsNotExist(err) {
					t.Fatal("read-only observer acquired state writer ownership")
				}
			}
			set := func(option, value string) []string {
				changed := slices.Clone(args)
				changed[slices.Index(changed, option)+1] = value
				return changed
			}
			t.Run("matched", func(t *testing.T) { check(t, args, 0, "", len(refs), true, true) })
			t.Run("repeat read-only observation", func(t *testing.T) { check(t, args, 0, "", len(refs), true, true) })
			t.Run("wrong verifier binary pin", func(t *testing.T) {
				check(t, set("--verifier-sha256", strings.Repeat("0", 64)), 2, "binary_mismatch", 0, false, false)
			})
			t.Run("wrong consumer binary pin", func(t *testing.T) {
				check(t, set("--consumer-sha256", strings.Repeat("0", 64)), 2, "binary_mismatch", 0, false, false)
			})
			t.Run("context drift", func(t *testing.T) {
				check(t, set("--expect-context", strings.Repeat("1", 64)), 2, "process_failure", 0, true, false)
			})
			t.Run("retention drift", func(t *testing.T) { check(t, set("--retain-headers", "17"), 2, "process_failure", 0, true, false) })
			t.Run("wrong target", func(t *testing.T) {
				e := losslessObject(t, marshalCLIValue(t, expected))
				e["targets"].([]any)[0].(map[string]any)["account_header"].(map[string]any)["hash"] = strings.Repeat("2", 64)
				path := writeCLIJSON(t, dir, "PRIVATE_WRONG_TARGET.json", e)
				defer protectCLIState(t, path)()
				check(t, set("--expectations", path), 2, "target_mismatch", 0, true, true)
			})
			t.Run("wrong tip", func(t *testing.T) {
				e := losslessObject(t, marshalCLIValue(t, expected))
				e["verification_tip"].(map[string]any)["height"] = headers[len(headers)-1].Height - 1
				path := writeCLIJSON(t, dir, "PRIVATE_WRONG_TIP.json", e)
				defer protectCLIState(t, path)()
				check(t, set("--expectations", path), 2, "report_mismatch", 0, true, true)
			})
			t.Run("unprovable guarantee", func(t *testing.T) {
				e := losslessObject(t, marshalCLIValue(t, expected))
				e["required_guarantees"] = []string{"CONTENT_INCLUSION", "STATE_VALUE_INCLUSION"}
				path := writeCLIJSON(t, dir, "PRIVATE_UNPROVABLE.json", e)
				defer protectCLIState(t, path)()
				check(t, set("--expectations", path), 2, "invalid_expectations", 0, true, true)
			})
			t.Run("headers cannot extend read-only query", func(t *testing.T) {
				b := bundle
				b.Headers = headers
				path := writeCLIJSON(t, dir, "PRIVATE_EXTENDING_BUNDLE.json", b)
				defer protectCLIState(t, path)()
				check(t, set("--bundle", path), 2, "process_failure", 0, true, false)
			})
		})
	}
}
