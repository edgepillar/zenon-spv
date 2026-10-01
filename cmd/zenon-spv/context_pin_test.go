package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func configurationJSON(t *testing.T, args []string, code int) configurationReport {
	t.Helper()
	var out, diagnostics bytes.Buffer
	got := runInspectConfig(append([]string{"--json"}, args...), &out, &diagnostics)
	if got != code || diagnostics.Len() != 0 || bytes.Contains(out.Bytes(), []byte("PRIVATE")) {
		t.Fatalf("configuration status or privacy mismatch: code=%d want=%d", got, code)
	}
	var report configurationReport
	decoder := json.NewDecoder(&out)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if decoder.Decode(new(any)) != io.EOF || report.SchemaVersion != 1 || report.Command != "inspect-config" || report.ExitCode != code || report.Trust == nil || len(report.Caveats) != 3 {
		t.Fatal("configuration report framing or envelope mismatch")
	}
	if code != 0 && (report.Context != nil || len(report.Trust) != 0 || report.Status != "error" || report.Error == nil) {
		t.Fatal("failed configuration exposed valid settings")
	}
	return report
}

func TestInspectConfigMatchesVerificationWithoutState(t *testing.T) {
	bundlePath, anchorPath := stateValueBundleFromLongChain(t, 6, nil)
	anchor, err := loadGenesis(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	profile := &verify.ProtocolProfile{Version: 1, Anchor: anchor, ValidThrough: anchor.Height + 100, Source: "PRIVATE_PROFILE_SOURCE"}
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "PRIVATE_PROFILE.json")
	writeQueryJSON(t, profilePath, profile)
	// Coverage is deliberately unrelated to the candidate heights: inspecting
	// supported settings does not promise authorization coverage for evidence.
	schedule, err := verify.NewProducerSchedule(anchor.ChainID,
		[]verify.ProducerCoverage{{FromHeight: 1, ThroughHeight: 1}},
		[]verify.ProducerEntry{{Height: 1, TimestampUnix: 10, ProducingAddr: chain.Address{1}}},
		[]string{"PRIVATE_PEER"}, map[string]uint64{"PRIVATE_PEER": 1})
	if err != nil {
		t.Fatal(err)
	}
	schedulePath := filepath.Join(dir, "PRIVATE_SCHEDULE.json")
	writeQueryJSON(t, schedulePath, schedule)
	args := []string{"--genesis-config", anchorPath, "--protocol-profile", profilePath}
	for _, required := range []bool{false, true} {
		selected := slices.Clone(args)
		if required {
			selected = append(selected, "--schedule", schedulePath)
		}
		r := configurationJSON(t, selected, 0)
		if r.Status != "configured" || r.Error != nil || r.Context == nil || r.Context.Fingerprint == nil || r.Context.Anchor != anchor {
			t.Fatal("configuration inspection lost supported settings")
		}
		pin := hex.EncodeToString(r.Context.Fingerprint[:])
		code := 0
		if required {
			code = 2 // Matching configuration cannot supply missing coverage.
		}
		verified := readVerificationReport(t, "verify-headers", append(selected, "--expect-context", pin, bundlePath), code)
		if !reflect.DeepEqual(verified.Context, r.Context) {
			t.Fatal("inspection did not describe the settings used by verification")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("configuration inspection created a state or lock file")
	}
	var out, diagnostics bytes.Buffer
	if runInspectConfig(args, &out, &diagnostics) != 0 || diagnostics.Len() != 0 {
		t.Fatal("text configuration inspection failed")
	}
	readCLIContext(t, out.String())
}

func TestInspectConfigErrorsArePrivate(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		code  int
		stage string
	}{
		{[]string{"--window", "PRIVATE_BAD_WINDOW"}, 64, "arguments"},
		{[]string{"--state", "PRIVATE_STATE"}, 64, "arguments"},
		{[]string{"--rpc", "PRIVATE_RPC"}, 64, "arguments"},
		{[]string{"PRIVATE_POSITIONAL"}, 64, "arguments"},
		{[]string{"--genesis-config", "PRIVATE_MISSING"}, 70, "genesis"},
	} {
		r := configurationJSON(t, tc.args, tc.code)
		if r.Error.Stage != tc.stage {
			t.Fatal("wrong configuration error stage")
		}
	}
	_, anchor := stateValueBundleFromLongChain(t, 6, nil)
	for _, flag := range []string{"--protocol-profile", "--schedule"} {
		configurationJSON(t, []string{"--genesis-config", anchor, flag, "PRIVATE_MISSING"}, 70)
	}
	for _, short := range []bool{false, true} {
		var diagnostics bytes.Buffer
		if runInspectConfig([]string{"--json", "--genesis-config", anchor}, reportFailWriter{short}, &diagnostics) != 70 || diagnostics.String() != "inspect-config: cannot write report\n" {
			t.Fatal("failed configuration output reported success or leaked diagnostics")
		}
	}
}

func TestContextPinPreservesOutcomesAndRejectsPolicyDrift(t *testing.T) {
	f := inspectionFixture(t, true)
	check := unchangedQueryFile(t, f.statePath)
	configArgs := append(slices.Clone(f.args[:2]), f.args[4:]...)
	c := configurationJSON(t, configArgs, 0).Context
	pin := strings.ToUpper(hex.EncodeToString(c.Fingerprint[:]))
	for _, command := range []string{"verify-headers", "verify-commitment", "verify-segment", "verify-state-value"} {
		args := append(slices.Clone(f.args), "--expect-context", pin)
		code := 0
		if command == "verify-headers" {
			code = 2 // No headers in the proof-only bundle.
		} else {
			args = append(args, "--retained-only")
			if command == "verify-state-value" {
				code = 2
			}
		}
		r := readVerificationReport(t, command, append(slices.Clone(args), f.bundlePath), code)
		if r.Error != nil || !reflect.DeepEqual(r.Context, c) {
			t.Fatal("matching pin altered the verification context or outcome")
		}
		wrong := readVerificationReport(t, command, append(args, "--window", "high", f.bundlePath), 70)
		if wrong.Error.Stage != "context_pin" || wrong.Outcome != nil || wrong.Context != nil || wrong.VerificationTip != nil || len(wrong.Results) != 0 {
			t.Fatal("changed policy reached proof verification")
		}
		check(t)
	}
	inspectionJSON(t, append(slices.Clone(f.args), "--expect-context", pin), 0)
	r := inspectionJSON(t, append(slices.Clone(f.args), "--expect-context", pin, "--window", "high"), 70)
	if r.Error.Stage != "context_pin" {
		t.Fatal("inspection ignored a mismatched pin")
	}
	check(t)
}

func TestMalformedContextPinIsNeverAnOmittedGuard(t *testing.T) {
	for _, pin := range []string{"", "PRIVATE_PIN", strings.Repeat("z", 64), strings.Repeat("0", 63), "0x" + strings.Repeat("0", 64), " " + strings.Repeat("0", 64)} {
		for _, command := range []string{"verify-headers", "verify-commitment", "verify-segment", "verify-state-value"} {
			r := readVerificationReport(t, command, []string{"--expect-context=" + pin, "PRIVATE_MISSING_BUNDLE"}, 64)
			if r.Error.Stage != "arguments" || r.Outcome != nil || len(r.Results) != 0 {
				t.Fatal("malformed pin reached verification setup")
			}
		}
		inspectionJSON(t, []string{"--expect-context=" + pin, "--state", "PRIVATE_MISSING_STATE"}, 64)
		code, out, diagnostics := captureSetupRun(t, func() int { return runWatch([]string{"--json", "--expect-context=" + pin}) })
		if code != 64 || out != "" || strings.Contains(diagnostics, "PRIVATE") {
			t.Fatal("watch ignored or disclosed a malformed pin")
		}
	}
}
