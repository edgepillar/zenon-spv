package conformance_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/verify"
)

// Measure the whole ordinary compiled consumer, including startup, bounded
// file decoding, trusted-state revalidation, inclusion checks and JSON output.
// Parent-side fixture expansion and builds occur before the measured process.
func TestCompiledContentScalingWorkflow(t *testing.T) {
	// An empty GOFLAGS alone falls back to Go's saved user settings. Prove the
	// measured child's build ignores that file rather than inheriting flags.
	goEnv := filepath.Join(t.TempDir(), "PRIVATE_GO_ENV")
	if err := os.WriteFile(goEnv, []byte("GOFLAGS=-not-a-real-build-flag\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOENV", goEnv)
	binary := buildQueryCLIs(t, "zenon-spv")["zenon-spv"]
	for _, grid := range flatWorkloads {
		name := flatWorkloadName(grid.members, grid.proofs)
		t.Run(name, func(t *testing.T) {
			w := newFlatWorkload(t, grid.members, grid.proofs)
			dir := t.TempDir()
			anchor := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", w.corpus.Anchor)
			profile := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", w.opts.Policy.ProtocolProfile)
			schedule := writeCLIJSON(t, dir, "PRIVATE_SCHEDULE.json", w.schedule)
			statePath := filepath.Join(dir, "PRIVATE_STATE.json")
			if err := w.state.Save(statePath); err != nil {
				t.Fatal(err)
			}
			unchanged := protectCLIState(t, statePath)
			defer unchanged()
			context, err := w.state.VerificationContext()
			if err != nil || context.Fingerprint == nil {
				t.Fatal("missing configured workload context")
			}
			common := []string{"--json", "--genesis-config", anchor, "--protocol-profile", profile, "--window", "low", "--schedule", schedule}
			inspected := runQueryCLI(t, binary, append([]string{"inspect-config"}, common...)...)
			assertOperatorPrivacy(t, inspected, dir)
			var config struct {
				Context verify.VerificationContext `json:"verification_context"`
			}
			if inspected.code != 0 || len(inspected.stderr) != 0 || json.Unmarshal(inspected.stdout, &config) != nil ||
				config.Context.Fingerprint == nil || *config.Context.Fingerprint != *context.Fingerprint {
				t.Fatal("compiled configuration differs from the selected trust context")
			}
			args := append([]string{"verify-commitment"}, common...)
			args = append(args, "--state", statePath, "--expect-context", hex.EncodeToString(context.Fingerprint[:]), "--retained-only", w.path)
			result := runQueryCLIWithResources(t, time.Minute, binary, args...)
			assertOperatorPrivacy(t, result, dir)
			report := checkProcessReport(t, result, 0, "ACCEPT")
			if report.Mode != "retained_only" || report.Persistence != "read_only" || report.Tip.Height != 6007 ||
				report.Tip.Hash != w.sample.Headers[6].HeaderHash || len(report.Results) != grid.proofs || report.Context == nil ||
				report.Context.Fingerprint == nil || *report.Context.Fingerprint != *context.Fingerprint {
				t.Fatal("compiled content query lost its retained state or pinned context")
			}
			for i, row := range report.Results {
				if row.Outcome != "ACCEPT" || row.Reference.Scope != "commitment" || row.Reference.Index == nil || *row.Reference.Index != i ||
					row.Reference.Account == nil || *row.Reference.Account != w.bundle.Commitments[i].Target ||
					!slices.Equal(row.Proven, []verify.Guarantee{verify.GuaranteeContentInclusion}) ||
					!slices.Contains(row.Trust, verify.TrustConfiguredAnchor) || !slices.Contains(row.Trust, verify.TrustPersistedState) ||
					!slices.Contains(row.Trust, verify.TrustExternalProducerSchedule) {
					t.Fatal("compiled query changed identity, inclusion or trust boundaries")
				}
			}
			unchanged()
			peak, source := result.memory.bytes, result.memory.source
			if peak == nil && (runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
				t.Fatal("missing supported process memory accounting")
			}
			record, err := json.Marshal(struct {
				Workload        string  `json:"workload"`
				MembersPerProof int     `json:"members_per_proof"`
				Proofs          int     `json:"proofs"`
				InputBytes      int64   `json:"input_bytes"`
				ElapsedNS       int64   `json:"elapsed_ns"`
				PeakRSSBytes    *uint64 `json:"peak_rss_bytes"`
				PeakRSSSource   string  `json:"peak_rss_source"`
			}{name, grid.members, grid.proofs, w.bytes, int64(result.elapsed), peak, source})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("offline-pilot-resource %s", record)
		})
	}
}
