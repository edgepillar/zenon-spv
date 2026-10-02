package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func selectedArguments() []string {
	args := []string{}
	for _, name := range []string{"verifier", "consumer", "genesis-config", "protocol-profile", "schedule", "state", "bundle", "expectations", "private-dir"} {
		args = append(args, "--"+name, "PRIVATE_"+name)
	}
	for _, name := range []string{"verifier-sha256", "consumer-sha256", "expect-context"} {
		args = append(args, "--"+name, strings.Repeat("a", 64))
	}
	return append(args, "--command", "verify-segment", "--window", "low", "--retain-headers", "16")
}

func TestExplicitConfiguration(t *testing.T) {
	args := selectedArguments()
	if c, ok := parseConfiguration(args); !ok || c.timeout != 30*time.Second {
		t.Fatal("complete explicit selection refused")
	}
	for i := 0; i < len(args); i += 2 {
		without := append(slices.Clone(args[:i]), args[i+2:]...)
		without = append(without, "--timeout", "1s")
		if _, ok := parseConfiguration(without); ok {
			t.Fatal("optional deadline replaced a mandatory input")
		}
		duplicate := append(slices.Clone(args), args[i:i+2]...)
		if _, ok := parseConfiguration(duplicate); ok {
			t.Fatal("duplicate selection accepted")
		}
	}
	for _, extra := range [][]string{
		{"--timeout", "0"}, {"--timeout", "-1s"}, {"--timeout", "61s"}, {"--timeout", "PRIVATE"},
		{"--timeout", "1s", "--timeout", "1s"}, {"--unknown", "PRIVATE"}, {"PRIVATE_POSITIONAL"},
	} {
		if _, ok := parseConfiguration(append(slices.Clone(args), extra...)); ok {
			t.Fatal("invalid invocation accepted")
		}
	}
	for _, tc := range []struct{ option, value string }{
		{"--command", "watch"}, {"--window", "PRIVATE"}, {"--retain-headers", "0"}, {"--retain-headers", "6"},
		{"--retain-headers", "4097"}, {"--retain-headers", "16.0"}, {"--expect-context", strings.Repeat("A", 64)}, {"--consumer-sha256", ""},
	} {
		changed := slices.Clone(args)
		changed[slices.Index(changed, tc.option)+1] = tc.value
		var out, diagnostics bytes.Buffer
		if run(context.Background(), changed, &out, &diagnostics) != 64 || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE") {
			t.Fatal("invalid selection executed or leaked private input")
		}
	}
}

func TestSummaryRequiresActualCompletionAndFixedShape(t *testing.T) {
	success := []byte("{\"schema_version\":1,\"status\":\"matched\",\"category\":null,\"checked_targets\":1}\n")
	zero := int64(0)
	if ok, category, count := matchSummary(success, &zero); !ok || category != "" || count != 1 {
		t.Fatal("complete matched summary refused")
	}
	for _, status := range []int64{-1, 2, 64, 70, 4294967295} {
		if ok, _, count := matchSummary(success, &status); ok || count != 0 {
			t.Fatal("failed process promoted a successful diagnostic")
		}
	}
	if ok, _, _ := matchSummary(success, nil); ok {
		t.Fatal("missing process status accepted")
	}
	for _, raw := range []string{
		strings.Replace(string(success), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		strings.Replace(string(success), `"schema_version":1`, `"schema_version":1,"schema_vers\u0069on":1`, 1),
		strings.Replace(string(success), `"schema_version":1`, `"Schema_version":1`, 1),
		strings.Replace(string(success), `"schema_version":1`, `"schema_version":1,"PRIVATE":0`, 1),
		strings.Replace(string(success), `"checked_targets":1`, `"checked_targets":1.0`, 1),
		strings.Replace(string(success), `"checked_targets":1`, `"checked_targets":0`, 1),
		strings.Replace(string(success), `"checked_targets":1`, `"checked_targets":257`, 1),
		strings.Replace(string(success), `"category":null,`, "", 1), string(success) + "{}", "PRIVATE", "{}", "null",
	} {
		if ok, category, count := matchSummary([]byte(raw), &zero); ok || count != 0 || strings.Contains(category, "PRIVATE") {
			t.Fatal("ambiguous summary accepted or leaked")
		}
	}
	two := int64(2)
	for _, category := range []string{"invalid_expectations", "target_mismatch", "guarantee_mismatch", "trust_mismatch"} {
		raw, _ := json.Marshal(consumption{Version: 1, Status: "not_matched", Category: &category})
		if ok, got, count := matchSummary(append(raw, '\n'), &two); ok || got != category || count != 0 {
			t.Fatal("known refusal lost its fixed category")
		}
	}
	private := "PRIVATE_CATEGORY"
	raw, _ := json.Marshal(consumption{Version: 1, Status: "not_matched", Category: &private})
	if ok, got, _ := matchSummary(append(raw, '\n'), &two); ok || got != "consumer_failure" {
		t.Fatal("unknown category disclosed")
	}
}

func TestBoundedLocalInputs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "PRIVATE_EXPECTATIONS")
	raw := []byte("PRIVATE")
	if os.WriteFile(path, raw, 0o600) != nil {
		t.Fatal("cannot create private input")
	}
	h := sha256.Sum256(raw)
	if _, ok := regularPath(path); !ok || !binaryMatches(path, hex.EncodeToString(h[:])) || binaryMatches(path, strings.Repeat("0", 64)) {
		t.Fatal("regular input identity check failed")
	}
	if got, ok := readExpectations(path); !ok || !bytes.Equal(got, raw) {
		t.Fatal("bounded input bytes changed")
	}
	for _, invalid := range []string{dir, filepath.Join(dir, "absent")} {
		if _, ok := regularPath(invalid); ok {
			t.Fatal("nonregular input accepted")
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err == nil {
		if _, ok := regularPath(link); ok {
			t.Fatal("symlinked selection accepted")
		}
	}
	if os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxExpectationsBytes+1), 0o600) != nil {
		t.Fatal("cannot create size boundary")
	}
	if _, ok := readExpectations(path); ok {
		t.Fatal("oversized expectations accepted")
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal("cannot create binary size boundary")
	}
	err = f.Truncate(maxBinaryBytes + 1)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal("cannot create binary size boundary")
	}
	if binaryMatches(path, strings.Repeat("0", 64)) {
		t.Fatal("oversized binary accepted")
	}
}

type shortWriter struct{}

func (shortWriter) Write(raw []byte) (int, error) { return len(raw) - 1, nil }

func TestCancellationAndOutputFailureRemainPrivate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, diagnostics bytes.Buffer
	if code := run(ctx, selectedArguments(), &out, &diagnostics); code != 2 || diagnostics.Len() != 0 || bytes.Contains(out.Bytes(), []byte("PRIVATE")) {
		t.Fatal("cancelled observation executed or leaked")
	}
	var r summary
	if json.Unmarshal(out.Bytes(), &r) != nil || r.Status != "not_matched" || r.Category == nil || *r.Category != "cancelled" || r.Verifier.ExitCode != nil || r.Consumer.ExitCode != nil {
		t.Fatal("cancelled observation acquired completion")
	}
	if run(ctx, selectedArguments(), shortWriter{}, &diagnostics) != 70 || strings.Contains(diagnostics.String(), "PRIVATE") {
		t.Fatal("short output treated as success or leaked")
	}
}

// A real child test process exercises portable cancellation, output bounds,
// exit status and stream separation without shell scripts or network access.
func TestObservationProcessHelper(t *testing.T) {
	if os.Getenv("ZENON_OBSERVER_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "success":
		_, _ = io.WriteString(os.Stdout, "ACCEPT\n")
	case "failed":
		_, _ = io.WriteString(os.Stdout, "ACCEPT\n")
		_, _ = io.WriteString(os.Stderr, "PRIVATE_DIAGNOSTIC\n")
		os.Exit(70)
	case "stdout limit":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, 4096))
	case "stderr limit":
		_, _ = os.Stderr.Write(bytes.Repeat([]byte{'x'}, 32768))
	case "sleep":
		time.Sleep(time.Minute)
	case "inherited pipe":
		binary, err := os.Executable()
		if err != nil {
			os.Exit(71)
		}
		child := exec.Command(binary, "-test.run=^TestObservationProcessHelper$", "--", "hold pipe")
		child.Stdout = os.Stdout
		if child.Start() != nil {
			os.Exit(71)
		}
		_ = child.Process.Release()
		_, _ = io.WriteString(os.Stdout, "ACCEPT\n")
	case "hold pipe":
		time.Sleep(3 * time.Second)
	default:
		os.Exit(64)
	}
	os.Exit(0)
}

func TestObservationProcessBoundaries(t *testing.T) {
	t.Setenv("ZENON_OBSERVER_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("cannot select helper binary")
	}
	for _, tc := range []struct {
		mode, category string
		timeout        time.Duration
	}{
		{"success", "", 5 * time.Second}, {"failed", "process_failure", 5 * time.Second},
		{"stdout limit", "output_limit", 5 * time.Second}, {"stderr limit", "output_limit", 5 * time.Second}, {"sleep", "timeout", 100 * time.Millisecond},
		{"inherited pipe", "process_failure", 5 * time.Second},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			r := runProcess(context.Background(), binary, []string{"-test.run=^TestObservationProcessHelper$", "--", tc.mode}, 32, tc.timeout)
			if r.category != tc.category || len(r.stdout) > 32 || r.ElapsedNS <= 0 {
				t.Fatal("process boundary disagreed with observation")
			}
			if tc.mode == "success" && (r.ExitCode == nil || *r.ExitCode != 0 || string(r.stdout) != "ACCEPT\n") {
				t.Fatal("successful process did not complete")
			}
			if tc.mode == "failed" && (r.ExitCode == nil || *r.ExitCode != 70 || r.StderrBytes == 0 || bytes.Contains(r.stdout, []byte("PRIVATE"))) {
				t.Fatal("actual failure or stream separation lost")
			}
			if tc.mode == "inherited pipe" && (r.ExitCode == nil || *r.ExitCode != 0 || string(r.stdout) != "ACCEPT\n" || r.code == 0) {
				t.Fatal("incomplete pipe delivery promoted successful process status")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := runProcess(ctx, binary, nil, 32, time.Second); r.category != "cancelled" || r.ExitCode != nil {
		t.Fatal("cancelled process acquired exit status")
	}
	if r := runProcess(context.Background(), filepath.Join(t.TempDir(), "PRIVATE_ABSENT"), nil, 32, time.Second); r.category != "process_unavailable" || r.ExitCode != nil {
		t.Fatal("failed start acquired exit status")
	}
}

func TestBoundedOutputDoesNotRetainDiagnostics(t *testing.T) {
	cancelled := false
	w := boundedOutput{limit: 10, cancel: func() { cancelled = true }}
	if n, err := w.Write([]byte("PRIVATE")); n != 7 || err != nil || w.buffer.Len() != 0 || w.observed != 7 {
		t.Fatal("diagnostics retained or counted incorrectly")
	}
	if _, err := w.Write([]byte("MORE")); err == nil || !cancelled || !w.exceeded {
		t.Fatal("diagnostic limit did not stop child")
	}
	if strconv.FormatInt(w.observed, 10) != "11" {
		t.Fatal("observed bytes did not include violating write")
	}
}
