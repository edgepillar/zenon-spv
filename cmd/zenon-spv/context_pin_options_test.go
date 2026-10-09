package main

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRepeatedContextPinCannotReplaceSelectedGuard(t *testing.T) {
	f := inspectionFixture(t, true)
	check := unchangedQueryFile(t, f.statePath)
	config := append(slices.Clone(f.args[:2]), f.args[4:]...)
	context := configurationJSON(t, config, 0).Context
	pin := hex.EncodeToString(context.Fingerprint[:])
	wrong := strings.Repeat("0", 64)
	if wrong == pin {
		wrong = strings.Repeat("1", 64)
	}
	// The second value would previously replace a separately selected guard,
	// including a malformed value, before a real retained proof was accepted.
	for _, tc := range []struct{ name, first string }{
		{"wrong_then_matching", wrong}, {"empty_then_matching", ""},
		{"private_then_matching", "PRIVATE_PIN"}, {"identical", pin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append(slices.Clone(f.args), "--retained-only", "--expect-context="+tc.first, "--expect-context", pin, f.bundlePath)
			r := readVerificationReport(t, "verify-commitment", args, 64)
			if r.Error == nil || r.Error.Stage != "arguments" || r.Error.Category != "usage" || r.Outcome != nil || r.Context != nil || r.VerificationTip != nil || len(r.Results) != 0 {
				t.Fatal("repeated pin reached state authorization or proof verification")
			}
			check(t)
		})
	}
}

func TestRepeatedContextPinStopsBeforeFilesLocksOrRPC(t *testing.T) {
	pin := strings.Repeat("1", 64)
	wrong := strings.Repeat("2", 64)
	cases := []struct {
		name string
		args []string
	}{
		{"identical_separate", []string{"--expect-context", pin, "--expect-context", pin}},
		{"wrong_then_matching", []string{"--expect-context", wrong, "--expect-context", pin}},
		{"matching_then_wrong", []string{"--expect-context", pin, "--expect-context", wrong}},
		{"empty_then_matching", []string{"--expect-context=", "--expect-context=" + pin}},
		{"private_then_matching", []string{"--expect-context=PRIVATE_PIN", "--expect-context", pin}},
		{"matching_then_private", []string{"--expect-context", pin, "--expect-context=PRIVATE_PIN"}},
		{"malformed_then_matching", []string{"--expect-context=" + strings.Repeat("z", 64), "--expect-context=" + pin}},
		{"single_dash", []string{"-expect-context", pin, "-expect-context", pin}},
		{"mixed_dash_and_equals", []string{"-expect-context=" + wrong, "--expect-context", pin}},
		{"uppercase_identical", []string{"--expect-context=" + strings.Repeat("a", 64), "-expect-context=" + strings.Repeat("A", 64)}},
		{"three_occurrences", []string{"--expect-context", pin, "--expect-context", wrong, "--expect-context", pin}},
	}
	var rpcCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rpcCalls.Add(1)
		http.Error(w, "unexpected fixture RPC", http.StatusInternalServerError)
	}))
	defer server.Close()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			missing := filepath.Join(dir, "PRIVATE_MISSING.json")
			args := append([]string{"--genesis-config", missing, "--protocol-profile", missing, "--schedule", missing, "--state", missing}, tc.args...)
			for _, command := range []string{"verify-headers", "verify-commitment", "verify-segment", "verify-state-value"} {
				r := readVerificationReport(t, command, append(slices.Clone(args), missing), 64)
				if r.Error == nil || r.Error.Stage != "arguments" || r.Error.Category != "usage" || r.Outcome != nil || r.Context != nil || r.VerificationTip != nil || len(r.Results) != 0 {
					t.Fatal("repeated pin did not stop before verification setup")
				}
			}
			r := inspectionJSON(t, args, 64)
			if r.Error == nil || r.Error.Stage != "arguments" || r.Error.Category != "usage" {
				t.Fatal("repeated pin did not stop before inspection setup")
			}
			for _, once := range []bool{false, true} {
				watchArgs := append([]string{"--json", "--rpc", server.URL}, args...)
				if once {
					watchArgs = append(watchArgs, "--once")
				}
				code, out, diagnostics := captureSetupRun(t, func() int { return runWatch(watchArgs) })
				if code != 64 || out != "" || diagnostics != "--expect-context must occur at most once\n" {
					t.Fatal("watch did not privately reject the repeated pin before startup")
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 || rpcCalls.Load() != 0 {
				t.Fatal("repeated pin created a file or lock, or contacted RPC")
			}
		})
	}
}

func TestRepeatedContextPinTextDiagnosticsArePrivate(t *testing.T) {
	args := []string{"--expect-context=PRIVATE_FIRST_PIN", "-expect-context=PRIVATE_LAST_PIN"}
	for _, command := range []string{"verify-headers", "verify-commitment", "verify-segment", "verify-state-value"} {
		var out, diagnostics bytes.Buffer
		code := runVerification(command, append(slices.Clone(args), "PRIVATE_BUNDLE"), &out, &diagnostics)
		if code != 64 || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE") {
			t.Fatal("text verification disclosed a repeated pin or evidence path")
		}
	}
	var out, diagnostics bytes.Buffer
	if runInspectState(append(slices.Clone(args), "--state", "PRIVATE_STATE"), &out, &diagnostics) != 64 || strings.Contains(out.String()+diagnostics.String(), "PRIVATE") {
		t.Fatal("text inspection disclosed a repeated pin or state path")
	}
	code, stdout, stderr := captureSetupRun(t, func() int { return runWatch(args) })
	if code != 64 || stdout != "" || stderr != "--expect-context must occur at most once\n" {
		t.Fatal("text watch disclosed a repeated pin")
	}
}
