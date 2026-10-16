package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func advancingArguments() []string {
	return append(selectedCollectionArguments(), "--advance-state-once", "--watch-safety-margin", "1", "--watch-batch-size", "3")
}

func TestAdvanceStateSelection(t *testing.T) {
	args := advancingArguments()
	c, ok := parseConfiguration(args)
	if !ok || !c.advance.enabled {
		t.Fatal("complete explicit advancement refused")
	}
	want := []string{"watch", "--json", "--once", "--rpc", c.collection.rpc, "--quorum", "1",
		"--genesis-config", c.anchor, "--protocol-profile", c.profile, "--schedule", c.schedule,
		"--state", c.state, "--expect-context", c.pin, "--window", c.window, "--retain-headers", c.retention,
		"--safety-margin", "1", "--batch-size", "3"}
	if !slices.Equal(advanceArguments(c), want) {
		t.Fatal("watch omitted or inferred a selected trust or policy input")
	}
	for _, extra := range [][]string{
		{"--advance-state-once"}, {"--advance-state-once=false"}, {"-advance-state-once=true"},
		{"--watch-safety-margin", "1"}, {"--watch-batch-size=3"},
	} {
		if _, ok := parseConfiguration(append(slices.Clone(args), extra...)); ok {
			t.Fatal("duplicate or disabled explicit advancement accepted")
		}
	}
	for _, option := range []string{"--advance-state-once", "--watch-safety-margin", "--watch-batch-size"} {
		without := slices.Clone(args)
		i := slices.Index(without, option)
		n := 2
		if option == "--advance-state-once" {
			n = 1
		}
		without = append(without[:i:i], without[i+n:]...)
		if _, ok := parseConfiguration(without); ok {
			t.Fatal("incomplete advancement selection accepted")
		}
	}
	for _, extra := range [][]string{
		{"--advance-state-once"}, {"--watch-safety-margin", "1"}, {"--watch-batch-size", "3"},
		{"--advance-state-once", "--watch-safety-margin", "1", "--watch-batch-size", "3"},
	} {
		if _, ok := parseConfiguration(append(selectedArguments(), extra...)); ok {
			t.Fatal("local-file mode can acquire a state writer")
		}
	}
	for _, option := range []string{"--watch-safety-margin", "--watch-batch-size"} {
		for _, value := range []string{"", "-1", "+1", "01", "0x1", "1.0", " 1", "true", "18446744073709551616"} {
			changed := slices.Clone(args)
			changed[slices.Index(changed, option)+1] = value
			if _, ok := parseConfiguration(changed); ok {
				t.Fatal("noncanonical or overflowing watch policy accepted")
			}
		}
	}
	for _, value := range []string{"0", "17"} {
		changed := slices.Clone(args)
		changed[slices.Index(changed, "--watch-batch-size")+1] = value
		if _, ok := parseConfiguration(changed); ok {
			t.Fatal("batch outside explicit retention bound accepted")
		}
	}
	for _, value := range []string{"0", "18446744073709551615"} {
		changed := slices.Clone(args)
		changed[slices.Index(changed, "--watch-safety-margin")+1] = value
		if _, ok := parseConfiguration(changed); !ok {
			t.Fatal("explicit full-width margin refused")
		}
	}
}

// TestMain dispatches this fixture before the normal test harness. No shell,
// network, real verifier state or real watch diagnostic is used here.
func advancementFixtureChild() {
	if len(os.Args) > 1 && os.Args[1] == "watch" {
		mode := os.Getenv("ZENON_OBSERVER_ADVANCE_MODE")
		switch mode {
		case "failed":
			_, _ = os.Stdout.WriteString("ACCEPT\n")
			os.Exit(70)
		case "sleep":
			time.Sleep(time.Minute)
		case "stdout_limit":
			_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, maxReportBytes+1))
		case "stderr_limit":
			_, _ = os.Stderr.Write(bytes.Repeat([]byte{'x'}, (16<<10)+1))
		default:
			state := os.Args[slices.Index(os.Args, "--state")+1]
			if os.WriteFile(state, []byte("ADVANCED_PRIVATE_STATE"), 0o600) != nil {
				os.Exit(71)
			}
			_, _ = os.Stdout.WriteString("fixture process completion only\n")
		}
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "--rpc" {
		_ = os.WriteFile(os.Getenv("ZENON_OBSERVER_ADVANCE_COLLECTED"), []byte("started"), 0o600)
		_, _ = os.Stdout.WriteString("{}\n")
		os.Exit(0)
	}
	_ = os.WriteFile(os.Getenv("ZENON_OBSERVER_ADVANCE_QUERIED"), []byte("started"), 0o600)
	os.Exit(70)
}

func TestAdvanceFailureStopsCollection(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	t.Setenv("ZENON_OBSERVER_ADVANCE_TEST", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	for _, tc := range []struct {
		name, mode, category string
		collected            bool
		mismatchedBinary     string
	}{
		{"failed_after_success_text", "failed", "process_failure", false, ""},
		{"deadline", "sleep", "timeout", false, ""},
		{"stdout_cap", "stdout_limit", "output_limit", false, ""},
		{"stderr_cap", "stderr_limit", "output_limit", false, ""},
		{"later_query_failure_keeps_saved_state", "success", "process_failure", true, ""},
		{"collector_pin_checked_before_watch", "success", "binary_mismatch", false, "collector"},
		{"verifier_pin_checked_before_watch", "success", "binary_mismatch", false, "verifier"},
		{"consumer_pin_checked_before_watch", "success", "binary_mismatch", false, "consumer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			collected, queried := filepath.Join(dir, "COLLECTED"), filepath.Join(dir, "QUERIED")
			t.Setenv("ZENON_OBSERVER_ADVANCE_MODE", tc.mode)
			t.Setenv("ZENON_OBSERVER_ADVANCE_COLLECTED", collected)
			t.Setenv("ZENON_OBSERVER_ADVANCE_QUERIED", queried)
			args := advancingArguments()
			for _, name := range []string{"collector", "verifier", "consumer"} {
				args[slices.Index(args, "--"+name)+1] = binary
				args[slices.Index(args, "--"+name+"-sha256")+1] = hex.EncodeToString(hash[:])
			}
			if tc.mismatchedBinary != "" {
				args[slices.Index(args, "--"+tc.mismatchedBinary+"-sha256")+1] = strings.Repeat("0", 64)
			}
			for _, name := range []string{"genesis-config", "protocol-profile", "schedule", "state", "expectations"} {
				path := filepath.Join(dir, "PRIVATE_"+name)
				if os.WriteFile(path, []byte("PRIVATE_INPUT"), 0o600) != nil {
					t.Fatal("cannot prepare process fixture")
				}
				args[slices.Index(args, "--"+name)+1] = path
			}
			args[slices.Index(args, "--private-dir")+1] = dir
			timeout := "5s"
			if tc.mode == "sleep" {
				timeout = "100ms"
			}
			args = append(args, "--timeout", timeout)
			var out, diagnostics bytes.Buffer
			code := run(context.Background(), args, &out, &diagnostics)
			var result summary
			if code != 2 || diagnostics.Len() != 0 || json.Unmarshal(out.Bytes(), &result) != nil ||
				result.Version != 3 || result.Category == nil || *result.Category != tc.category || result.CheckedTargets != 0 ||
				result.Watch == nil || result.Collector == nil || result.Consumer.ExitCode != nil || bytes.Contains(out.Bytes(), []byte("PRIVATE")) {
				t.Fatal("watch failure lost actual metadata, started consumption or leaked inputs")
			}
			_, collectedErr := os.Stat(collected)
			_, queryErr := os.Stat(queried)
			if (collectedErr == nil) != tc.collected || (queryErr == nil) != tc.collected || (result.Collector.ExitCode != nil) != tc.collected {
				t.Fatal("watch completion did not gate every later child")
			}
			if tc.mismatchedBinary != "" && result.Watch.ExitCode != nil {
				t.Fatal("preflight refusal started the state writer")
			}
			state, _ := os.ReadFile(args[slices.Index(args, "--state")+1])
			if tc.collected {
				if result.Watch.ExitCode == nil || *result.Watch.ExitCode != 0 || !bytes.Equal(state, []byte("ADVANCED_PRIVATE_STATE")) {
					t.Fatal("later failure rolled back state or fabricated watch completion")
				}
			} else if !bytes.Equal(state, []byte("PRIVATE_INPUT")) {
				t.Fatal("refused watch fixture changed selected state")
			}
		})
	}
}
