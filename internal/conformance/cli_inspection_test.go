package conformance_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/0x3639/zenon-spv/internal/statelock"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Decode the shipped inspection schema independently of the command package.
type cliInspectionReport struct {
	SchemaVersion uint32                            `json:"schema_version"`
	Command       string                            `json:"command"`
	Status        string                            `json:"status"`
	ExitCode      int                               `json:"exit_code"`
	Reason        *string                           `json:"reason"`
	Error         *struct{ Stage, Category string } `json:"error"`
	Persistence   string                            `json:"persistence"`
	Context       *verify.VerificationContext       `json:"verification_context"`
	Window        *verify.RetainedSummary           `json:"retained_window"`
	StateTrust    []verify.TrustAssumption          `json:"state_trust"`
	Caveats       []string                          `json:"caveats"`
}

func TestCompiledCLIStateCountBound(t *testing.T) {
	binary := buildQueryCLIs(t, "zenon-spv")["zenon-spv"]
	c, _ := contractBatchBundle(t)
	dir := t.TempDir()
	anchor := writeCLIJSON(t, dir, "anchor.json", c.Chain.Anchor)
	statePath := filepath.Join(dir, "PRIVATE_STATE.json")
	raw := []byte(fmt.Sprintf(`{"version":1,"genesis":%s,"capacity":%d,"retained_window":[%s"PRIVATE_UNREACHED_ROW"]}`,
		readCLIFile(t, anchor), verify.MaxPersistedHeaders, strings.Repeat("null,", verify.MaxPersistedHeaders)))
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	unchanged := protectCLIState(t, statePath)
	t.Cleanup(unchanged)
	result := runQueryCLI(t, binary, "inspect-state", "--json", "--genesis-config", anchor, "--state", statePath)
	if result.code != 70 || len(result.stderr) != 0 || bytes.Contains(result.stdout, []byte("PRIVATE")) {
		t.Fatal("over-limit state did not produce a privacy-safe operational error")
	}
	var report cliInspectionReport
	d := json.NewDecoder(bytes.NewReader(result.stdout))
	d.DisallowUnknownFields()
	if err := d.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if err := d.Decode(new(any)); err != io.EOF || report.SchemaVersion != 1 || report.Command != "inspect-state" || report.Status != "error" || report.ExitCode != 70 || report.Persistence != "read_only" {
		t.Fatal("over-limit state lost its inspection error classification")
	}
	if report.Error == nil || report.Error.Stage != "state" || report.Error.Category != "operational" || report.Reason != nil || report.Context != nil || report.Window != nil || len(report.StateTrust) != 0 {
		t.Fatal("over-limit state exposed partial retained evidence")
	}
	if _, err := os.Stat(statePath + ".lock"); !os.IsNotExist(err) {
		t.Fatal("failed read-only inspection created a writer companion")
	}
}

func TestCompiledCLIStateInspection(t *testing.T) {
	binary := buildQueryCLIs(t, "zenon-spv")["zenon-spv"]
	c, seed := contractBatchBundle(t)
	dir := t.TempDir()
	anchor := writeCLIJSON(t, dir, "anchor.json", c.Chain.Anchor)
	seedPath := writeCLIJSON(t, dir, "seed.json", seed)
	seedState := filepath.Join(dir, "seed-state.json")
	checkProcessReport(t, runQueryCLI(t, binary, "verify-headers", "--json", "--genesis-config", anchor, "--state", seedState, seedPath), 0, "ACCEPT")
	statePath := filepath.Join(dir, "PRIVATE_STATE.json")
	if err := os.WriteFile(statePath, readCLIFile(t, seedState), 0o600); err != nil {
		t.Fatal(err)
	}
	stateUnchanged := protectCLIState(t, statePath)
	t.Cleanup(stateUnchanged)
	common := []string{"--json", "--genesis-config", anchor, "--state", statePath}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	run := func(args []string, code int, status string) cliInspectionReport {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, append([]string{"inspect-state"}, args...)...)
		cmd.Env = append(queryCLIEnvironment(), "ZENON_SPV_RPC="+server.URL+"/PRIVATE_RPC", "ZENON_SPV_PEERS="+server.URL+"/PRIVATE_PEERS")
		var out, diagnostics bytes.Buffer
		cmd.Stdout, cmd.Stderr, cmd.WaitDelay = &out, &diagnostics, time.Second
		err := cmd.Run()
		got := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal(err)
			}
			got = exit.ExitCode()
		}
		if ctx.Err() != nil || got != code || diagnostics.Len() != 0 || requests.Load() != 0 || bytes.Contains(out.Bytes(), []byte("PRIVATE")) {
			t.Fatalf("inspection process failed, disclosed input, or accessed RPC: code=%d want=%d error=%v", got, code, err)
		}
		var report cliInspectionReport
		decoder := json.NewDecoder(&out)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&report); err != nil {
			t.Fatal(err)
		}
		if err := decoder.Decode(new(any)); err != io.EOF || report.SchemaVersion != 1 || report.Command != "inspect-state" || report.ExitCode != code || report.Status != status || report.Persistence != "read_only" {
			t.Fatal("inspection framing, status, or identity mismatch")
		}
		if code != 0 && (report.Context != nil || report.Window != nil || len(report.StateTrust) != 0) {
			t.Fatal("failed inspection claimed an authorized window")
		}
		stateUnchanged()
		return report
	}
	r := run(common, 0, "inspected")
	if r.Error != nil || r.Reason != nil || r.Context == nil || r.Context.Anchor != c.Chain.Anchor ||
		r.Window == nil || r.Window.Count != 7 || r.Window.Capacity != 7 || r.Window.Oldest.Height != 4003 || r.Window.Tip.Height != 4009 ||
		r.Window.Oldest.Hash != seed.Headers[2].HeaderHash || r.Window.Tip.Hash != seed.Headers[8].HeaderHash ||
		r.Window.DepthEligible == nil || r.Window.DepthEligible.FromHeight != 4003 || r.Window.DepthEligible.ThroughHeight != 4003 ||
		!slices.Contains(r.StateTrust, verify.TrustPersistedState) || len(r.Caveats) < 3 {
		t.Fatal("inspection differs from the independently pinned retained window")
	}
	text := runQueryCLI(t, binary, append([]string{"inspect-state"}, common[1:]...)...)
	if text.code != 0 || len(text.stderr) != 0 {
		t.Fatal("text inspection did not complete successfully")
	}
	for _, want := range []string{
		"oldest: 4003 " + hex.EncodeToString(seed.Headers[2].HeaderHash[:]) + "\n",
		"tip: 4009 " + hex.EncodeToString(seed.Headers[8].HeaderHash[:]) + "\n",
	} {
		if !bytes.Contains(text.stdout, []byte(want)) {
			t.Fatal("compiled text report did not render full hexadecimal header identities")
		}
	}
	stateUnchanged()
	r = run(append(slices.Clone(common), "--window", "medium"), 0, "inspected")
	if r.Window == nil || r.Window.DepthEligible != nil || r.Window.Capacity != 61 || r.Context.Policy.W != 60 {
		t.Fatal("successful inspection claimed unavailable proof depth")
	}
	missing := filepath.Join(dir, "PRIVATE_MISSING.json")
	r = run(append(slices.Clone(common), "--state", missing), 2, "refused")
	if r.Reason == nil || *r.Reason != "ReasonMissingEvidence" || r.Error != nil {
		t.Fatal("missing state lost its explicit refusal")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("inspection initialized a missing state")
	}
	for _, tc := range []struct {
		args  []string
		code  int
		stage string
	}{
		{[]string{"--window", "PRIVATE_WINDOW"}, 64, "arguments"},
		{[]string{"--genesis-config", missing}, 70, "genesis"},
		{[]string{"--state", anchor}, 70, "state"},
	} {
		r = run(append(slices.Clone(common), tc.args...), tc.code, "error")
		if r.Error == nil || r.Error.Stage != tc.stage {
			t.Fatal("inspection error lost its stage")
		}
	}
	for _, path := range []string{statePath, missing, anchor} {
		if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
			t.Fatal("inspection created a writer companion")
		}
	}
	lock, err := statelock.Acquire(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	run(common, 0, "inspected")
	if other, err := statelock.Acquire(statePath); err == nil {
		_ = other.Close()
		t.Fatal("inspection process interfered with active writer ownership")
	}
}
