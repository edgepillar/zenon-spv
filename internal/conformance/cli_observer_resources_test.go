package conformance_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Observe the complete ordinary observer -> verifier -> consumer invocation.
// Fixtures, builds and preservation checks stay outside the group timer. The
// native waited-process memory counter is not simultaneous process-tree memory;
// on Unix it may include inherited accounting from reaped descendants.
func TestCompiledBlockObserverResources(t *testing.T) {
	bins := buildQueryCLIs(t, "zenon-spv", "consume-query-report", "observe-block")
	binaryHash := func(name string) string {
		raw, err := os.ReadFile(bins[name])
		if err != nil {
			t.Fatal("cannot identify selected resource binary")
		}
		hash := sha256.Sum256(raw)
		return hex.EncodeToString(hash[:])
	}
	verifierHash, consumerHash := binaryHash("zenon-spv"), binaryHash("consume-query-report")
	const targets = 16
	flat := newFlatWorkload(t, 1000, targets)
	for _, capacity := range []int{256, verify.MaxRetainHeaders} {
		// Only the content list and independently selected member identities
		// reuse the pinned node-derived corpus. The full retained header window,
		// anchor, profile and schedule are synthetic stress inputs.
		w := newRetainedContentWorkload(t, capacity, flat.corpus.Anchor.ChainID, flat.bundle.Commitments[0].Flat.SortedHeaders)
		retained, err := w.state.RetainedSummary()
		if err != nil || retained.Count != capacity || retained.Capacity != capacity {
			t.Fatal("resource window is not completely populated")
		}
		context, err := w.state.VerificationContext()
		if err != nil || context.Fingerprint == nil {
			t.Fatal("resource window has no selected context")
		}
		pin := hex.EncodeToString(context.Fingerprint[:])
		dir := t.TempDir()
		anchor := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", w.anchor)
		profile := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", w.opts.Policy.ProtocolProfile)
		schedule := writeCLIJSON(t, dir, "PRIVATE_SCHEDULE.json", w.opts.ProducerAuth.Authorizer.(*verify.ScheduleAuthorizer).Schedule)
		bundle := proof.HeaderBundle{Version: proof.WireVersion, ChainID: w.anchor.ChainID, ClaimedGenesis: w.anchor.HeaderHash}
		refs := make([]any, targets)
		for i, selected := range flat.bundle.Commitments {
			selected.Height = w.evidence.Height
			bundle.Commitments = append(bundle.Commitments, selected)
			refs[i] = map[string]any{"scope": "commitment", "index": i, "momentum_height": selected.Height, "account_header": selected.Target}
			if result := w.state.VerifyCommitment(selected); result.Outcome != verify.OutcomeAccept {
				t.Fatal("selected resource target is not retained and depth eligible")
			}
		}
		bundlePath := writeCLIJSON(t, dir, "PRIVATE_BUNDLE.json", bundle)
		expected := writeCLIJSON(t, dir, "PRIVATE_EXPECTATIONS.json", map[string]any{
			"schema_version": 1, "command": "verify-commitment", "context_fingerprint": pin,
			"verification_tip": retained.Tip, "targets": refs, "required_guarantees": []string{"CONTENT_INCLUSION"},
			"allowed_trust_assumptions": []string{"TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_RETAINED_WINDOW_DEPTH",
				"TRUST_EXTERNAL_PROTOCOL_PROFILE", "TRUST_EXTERNAL_PRODUCER_SCHEDULE"},
		})
		paths := []string{anchor, profile, schedule, w.path, bundlePath, expected}
		guards := make([]func(), len(paths))
		for i, path := range paths {
			guards[i] = protectCLIState(t, path)
		}
		for _, concurrency := range []int{1, 4} {
			name := fmt.Sprintf("K%d_T%d_C%d", capacity, targets, concurrency)
			t.Run(name, func(t *testing.T) {
				private := filepath.Join(t.TempDir(), "PRIVATE_RUNS")
				if os.Mkdir(private, 0o700) != nil {
					t.Fatal("cannot create private resource directory")
				}
				args := []string{"--verifier", bins["zenon-spv"], "--verifier-sha256", verifierHash,
					"--consumer", bins["consume-query-report"], "--consumer-sha256", consumerHash,
					"--command", "verify-commitment", "--genesis-config", anchor, "--protocol-profile", profile, "--schedule", schedule,
					"--state", w.path, "--bundle", bundlePath, "--expectations", expected, "--private-dir", private,
					"--expect-context", pin, "--window", "low", "--retain-headers", strconv.Itoa(capacity), "--timeout", "30s"}
				for round := range 21 {
					results := make([]queryCLIResult, concurrency)
					completed := make([]bool, concurrency)
					var joined sync.WaitGroup
					start := make(chan struct{})
					for slot := range concurrency {
						joined.Add(1)
						go func() {
							defer joined.Done()
							<-start
							results[slot] = runQueryCLIWithResources(t, time.Minute, bins["observe-block"], args...)
							completed[slot] = true
						}()
					}
					started := time.Now()
					close(start)
					joined.Wait()
					elapsed := time.Since(started).Nanoseconds()
					type processObservation struct {
						Slot             int                   `json:"slot"`
						ActualExit       int                   `json:"actual_exit"`
						ElapsedNS        int64                 `json:"elapsed_ns"`
						WaitedPeakBytes  *uint64               `json:"waited_peak_bytes"`
						WaitedPeakSource string                `json:"waited_peak_source"`
						ObserverNS       int64                 `json:"observer_elapsed_ns"`
						CheckedTargets   int                   `json:"checked_targets"`
						Verifier         observerProcessRecord `json:"verifier"`
						Consumer         observerProcessRecord `json:"consumer"`
					}
					observations := make([]processObservation, concurrency)
					for slot, result := range results {
						var report struct {
							Version   int                   `json:"schema_version"`
							Status    string                `json:"status"`
							Category  *string               `json:"category"`
							Count     int                   `json:"checked_targets"`
							ElapsedNS int64                 `json:"elapsed_ns"`
							Verifier  observerProcessRecord `json:"verifier"`
							Consumer  observerProcessRecord `json:"consumer"`
						}
						if !completed[slot] || result.code != 0 || len(result.stderr) != 0 || json.Unmarshal(result.stdout, &report) != nil ||
							report.Version != 1 || report.Status != "matched" || report.Category != nil || report.Count != targets ||
							report.ElapsedNS <= 0 || result.elapsed <= 0 || len(losslessObject(t, result.stdout)) != 7 {
							t.Fatalf("observer resource round %d slot %d did not complete its selected workflow (actual exit %d)", round, slot, result.code)
						}
						for _, child := range []observerProcessRecord{report.Verifier, report.Consumer} {
							if child.ExitCode == nil || *child.ExitCode != 0 || child.ElapsedNS <= 0 || child.StdoutBytes <= 0 || child.StderrBytes != 0 {
								t.Fatal("resource observation lost successful child completion")
							}
						}
						if report.Verifier.StdoutBytes > 4<<20 || report.Consumer.StdoutBytes > 1024 ||
							result.memory.bytes == nil && (runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
							t.Fatal("resource observation exceeded output bounds or lost native accounting")
						}
						observations[slot] = processObservation{slot, result.code, int64(result.elapsed), result.memory.bytes, result.memory.source,
							report.ElapsedNS, report.Count, report.Verifier, report.Consumer}
					}
					// A fixed numeric record is retained before post-run file checks.
					// Do not retry failures, filter a slow round or sort process slots.
					record, err := json.Marshal(struct {
						Workload          string               `json:"workload"`
						Round             int                  `json:"round"`
						Capacity          int                  `json:"retained_headers"`
						Targets           int                  `json:"targets"`
						Concurrency       int                  `json:"concurrency"`
						StateBytes        int64                `json:"state_bytes"`
						BundleBytes       int                  `json:"bundle_bytes"`
						ExpectationsBytes int                  `json:"expectations_bytes"`
						GroupElapsedNS    int64                `json:"group_elapsed_ns"`
						Observations      []processObservation `json:"observations"`
					}{name, round, capacity, targets, concurrency, w.bytes, len(readCLIFile(t, bundlePath)), len(readCLIFile(t, expected)), elapsed, observations})
					if err != nil {
						t.Fatal("cannot encode fixed observer resource record")
					}
					t.Logf("offline-observer-workflow-resource %s", record)
					for _, guard := range guards {
						guard()
					}
					entries, err := os.ReadDir(private)
					if err != nil || len(entries) != 0 {
						t.Fatal("resource observer left private run files behind")
					}
					if _, err := os.Stat(w.path + ".lock"); !os.IsNotExist(err) {
						t.Fatal("read-only resource workload acquired writer ownership")
					}
				}
			})
		}
	}
}
