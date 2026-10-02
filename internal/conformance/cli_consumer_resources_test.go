package conformance_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// Measure only the ordinary report-consumer process. Node-derived workload
// expansion, verifier execution, file capture and compilation happen first.
// Preserve every ordered observation; do not retry failures or select outliers.
// These synthetic batches are not a real application's traffic distribution.
func TestCompiledQueryConsumerScaling(t *testing.T) {
	bins := buildQueryCLIs(t, "zenon-spv", "consume-query-report")
	for _, targets := range []int{1, 16, 256} {
		name := "T" + strconv.Itoa(targets)
		t.Run(name, func(t *testing.T) {
			w := newFlatWorkload(t, 1000, targets)
			dir := t.TempDir()
			anchor := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", w.corpus.Anchor)
			profile := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", w.opts.Policy.ProtocolProfile)
			schedule := writeCLIJSON(t, dir, "PRIVATE_SCHEDULE.json", w.schedule)
			statePath := filepath.Join(dir, "PRIVATE_STATE.json")
			if err := w.state.Save(statePath); err != nil {
				t.Fatal(err)
			}
			stateUnchanged := protectCLIState(t, statePath)
			defer stateUnchanged()
			context, err := w.state.VerificationContext()
			if err != nil || context.Fingerprint == nil {
				t.Fatal("selected workload settings have no fingerprint")
			}
			pin := hex.EncodeToString(context.Fingerprint[:])
			// Independent expectations use selected corpus identities/settings,
			// never fields copied out of the candidate query diagnostic.
			refs := make([]any, targets)
			for i, evidence := range w.bundle.Commitments {
				refs[i] = map[string]any{"scope": "commitment", "index": i, "momentum_height": evidence.Height, "account_header": evidence.Target}
			}
			expectedPath := writeCLIJSON(t, dir, "PRIVATE_EXPECTATIONS.json", map[string]any{
				"schema_version": 1, "command": "verify-commitment", "context_fingerprint": pin,
				"verification_tip": map[string]any{"height": w.sample.Headers[6].Height, "hash": w.sample.Headers[6].HeaderHash},
				"targets":          refs, "required_guarantees": []string{"CONTENT_INCLUSION"},
				"allowed_trust_assumptions": []string{"TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_EXTERNAL_PROTOCOL_PROFILE",
					"TRUST_EXTERNAL_PRODUCER_SCHEDULE", "TRUST_RETAINED_WINDOW_DEPTH"},
			})
			expectedBytes := len(readCLIFile(t, expectedPath))
			args := []string{"verify-commitment", "--json", "--genesis-config", anchor, "--protocol-profile", profile,
				"--schedule", schedule, "--window", "low", "--state", statePath, "--expect-context", pin, "--retained-only", w.path}
			verified := runQueryCLI(t, bins["zenon-spv"], args...)
			assertOperatorPrivacy(t, verified, dir)
			checkProcessReport(t, verified, 0, "ACCEPT")
			reportPath := filepath.Join(dir, "PRIVATE_REPORT.json")
			if err := os.WriteFile(reportPath, verified.stdout, 0o600); err != nil {
				t.Fatal(err)
			}
			reportUnchanged, expectedUnchanged := protectCLIState(t, reportPath), protectCLIState(t, expectedPath)
			defer reportUnchanged()
			defer expectedUnchanged()
			want := fmt.Sprintf("{\"schema_version\":1,\"status\":\"matched\",\"category\":null,\"checked_targets\":%d}\n", targets)
			type observation struct {
				ElapsedNS     int64   `json:"elapsed_ns"`
				PeakRSSBytes  *uint64 `json:"peak_rss_bytes"`
				PeakRSSSource string  `json:"peak_rss_source"`
			}
			observations := make([]observation, 0, 21)
			for range 21 {
				result := runQueryCLIWithResources(t, time.Minute, bins["consume-query-report"], "--report", reportPath,
					"--expectations", expectedPath, "--verifier-exit-code", strconv.Itoa(verified.code))
				if result.code != 0 || len(result.stderr) != 0 || string(result.stdout) != want {
					t.Fatal("measured consumer did not match the complete selected batch")
				}
				peak, source := result.memory.bytes, result.memory.source
				if peak == nil && (runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
					t.Fatal("missing supported consumer process memory accounting")
				}
				observations = append(observations, observation{int64(result.elapsed), peak, source})
				stateUnchanged()
				reportUnchanged()
				expectedUnchanged()
			}
			record, err := json.Marshal(struct {
				Workload          string        `json:"workload"`
				Targets           int           `json:"targets"`
				ReportBytes       int           `json:"report_bytes"`
				ExpectationsBytes int           `json:"expectations_bytes"`
				ElapsedNS         int64         `json:"elapsed_ns"`
				PeakRSSBytes      *uint64       `json:"peak_rss_bytes"`
				PeakRSSSource     string        `json:"peak_rss_source"`
				Observations      []observation `json:"observations"`
			}{name, targets, len(verified.stdout), expectedBytes, observations[0].ElapsedNS,
				observations[0].PeakRSSBytes, observations[0].PeakRSSSource, observations})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("offline-pilot-query-resource %s", record)
		})
	}
}
