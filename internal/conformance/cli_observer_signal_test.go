package conformance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/statelock"
)

const observerSignalHelper = "ZENON_OBSERVER_SIGNAL_HELPER"

// Only a selected child copy of this test executable takes this path. The
// ordinary observer is built from its shipped command, without this fixture.
// Controlled children isolate signal delivery, joined completion and private
// staging; they do not authenticate headers or execute the strict consumer.
func init() {
	if os.Getenv(observerSignalHelper) != "1" || len(os.Args) < 2 {
		return
	}
	phase := ""
	switch os.Args[1] {
	case "verify-segment":
		phase = "verifier"
	case "--report":
		phase = "consumer"
	default:
		return
	}
	if phase != os.Getenv("ZENON_OBSERVER_SIGNAL_PHASE") {
		if phase == "verifier" {
			_, _ = io.WriteString(os.Stdout, "{}\n")
			os.Exit(0)
		}
		os.Exit(74)
	}
	dir := os.Getenv("ZENON_OBSERVER_SIGNAL_DIRECTORY")
	lock, err := statelock.Acquire(filepath.Join(dir, "child"))
	if err != nil {
		os.Exit(74)
	}
	if phase == "consumer" {
		_, _ = io.WriteString(os.Stdout, "{\"schema_version\":1,\"status\":\"matched\",\"category\":null,\"checked_targets\":1}\n")
	} else {
		_, _ = io.WriteString(os.Stdout, "{\"PRIVATE_PARTIAL_REPORT\":")
	}
	_, _ = io.WriteString(os.Stderr, "PRIVATE_SIGNAL_DIAGNOSTIC\n")
	if os.WriteFile(filepath.Join(dir, "ready"), []byte("ready\n"), 0o600) != nil {
		os.Exit(74)
	}
	// Explicit release also settles the fixture if the baseline observer exits
	// without cancelling its child. No unrelated process is signalled.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
			_ = lock.Close()
			os.Exit(0)
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = lock.Close()
	os.Exit(75)
}

func TestCompiledObserverSignalCancellation(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("native SIGINT/SIGTERM delivery is selected only on Linux and macOS")
	}
	observer := buildQueryCLIs(t, "observe-block")["observe-block"]
	helper, err := os.Executable()
	if err != nil {
		t.Fatal("cannot select controlled child executable")
	}
	childBytes := readCLIFile(t, helper)
	childHash := sha256.Sum256(childBytes)
	pin := hex.EncodeToString(childHash[:])
	for _, phase := range []string{"verifier", "consumer"} {
		for _, signal := range []struct {
			name  string
			value os.Signal
		}{{"interrupt", os.Interrupt}, {"termination", syscall.SIGTERM}} {
			t.Run(phase+"/"+signal.name, func(t *testing.T) {
				dir := t.TempDir()
				input := filepath.Join(dir, "PRIVATE_INPUT.json")
				const original = "{\"PRIVATE_UNCHANGED_INPUT\":true}\n"
				if os.WriteFile(input, []byte(original), 0o600) != nil {
					t.Fatal("cannot prepare protected input")
				}
				unchanged := protectCLIState(t, input)
				staging := filepath.Join(dir, "PRIVATE_STAGING")
				if os.Mkdir(staging, 0o700) != nil {
					t.Fatal("cannot create private staging parent")
				}
				args := []string{"--verifier", helper, "--consumer", helper,
					"--verifier-sha256", pin, "--consumer-sha256", pin,
					"--command", "verify-segment", "--genesis-config", input,
					"--protocol-profile", input, "--schedule", input, "--state", input,
					"--bundle", input, "--expectations", input, "--private-dir", staging,
					"--expect-context", strings.Repeat("a", 64), "--window", "low", "--retain-headers", "16"}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, observer, args...)
				cmd.Env = append(queryCLIEnvironment(), observerSignalHelper+"=1",
					"ZENON_OBSERVER_SIGNAL_PHASE="+phase, "ZENON_OBSERVER_SIGNAL_DIRECTORY="+dir,
					"GORACE=atexit_sleep_ms=0")
				cmd.WaitDelay = time.Second
				var out, diagnostics bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &diagnostics
				if cmd.Start() != nil {
					t.Fatal("cannot start ordinary observer")
				}
				joined := make(chan error, 1)
				go func() { joined <- cmd.Wait() }()
				settled := false
				t.Cleanup(func() {
					// Release a baseline child before joining or removing its
					// private fixture. Fixed observers cancel and join it first.
					if os.WriteFile(filepath.Join(dir, "release"), nil, 0o600) != nil {
						t.Error("cannot release controlled child")
					}
					cancel()
					if !settled {
						select {
						case <-joined:
						case <-time.After(10 * time.Second):
							t.Error("owned observer did not settle")
						}
					}
					if !waitObserverSignalLock(dir, 10*time.Second) {
						t.Error("controlled child outlived fixture cleanup")
					}
				})
				deadline := time.Now().Add(10 * time.Second)
				for {
					if raw, err := os.ReadFile(filepath.Join(dir, "ready")); err == nil && string(raw) == "ready\n" {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("controlled child did not establish readiness")
					}
					time.Sleep(5 * time.Millisecond)
				}
				lock, err := statelock.Acquire(filepath.Join(dir, "child"))
				if err == nil {
					_ = lock.Close()
					t.Fatal("ready child did not hold its lifetime lock")
				}
				if !errors.Is(err, statelock.ErrBusy) {
					t.Fatal("cannot establish controlled child lifetime")
				}
				if cmd.Process.Signal(signal.value) != nil {
					t.Fatal("cannot deliver selected signal to owned observer")
				}
				select {
				case err = <-joined:
					settled = true
				case <-ctx.Done():
					t.Fatal("signalled observer did not settle")
				}
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 2 || diagnostics.Len() != 0 {
					t.Fatalf("signal bypassed controlled refusal: exit=%v stderr_bytes=%d", cmd.ProcessState.ExitCode(), diagnostics.Len())
				}
				var report struct {
					Version        int                   `json:"schema_version"`
					Status         string                `json:"status"`
					Category       *string               `json:"category"`
					CheckedTargets int                   `json:"checked_targets"`
					Verifier       observerProcessRecord `json:"verifier"`
					Consumer       observerProcessRecord `json:"consumer"`
				}
				if json.Unmarshal(out.Bytes(), &report) != nil || report.Version != 1 || report.Status != "not_matched" ||
					report.Category == nil || *report.Category != "cancelled" || report.CheckedTargets != 0 ||
					bytes.Contains(out.Bytes(), []byte("PRIVATE")) {
					t.Fatal("cancelled process promoted a result or disclosed private bytes")
				}
				if report.Verifier.ExitCode == nil || (phase == "verifier" && (*report.Verifier.ExitCode == 0 || report.Consumer.ExitCode != nil)) ||
					(phase == "consumer" && (*report.Verifier.ExitCode != 0 || report.Consumer.ExitCode == nil || *report.Consumer.ExitCode == 0 ||
						report.Consumer.StdoutBytes != int64(len("{\"schema_version\":1,\"status\":\"matched\",\"category\":null,\"checked_targets\":1}\n")))) {
					t.Fatal("cancelled summary lost actual child completion")
				}
				if !waitObserverSignalLock(dir, time.Second) {
					t.Fatal("cancelled child retained lifetime ownership after observer completion")
				}
				entries, err := os.ReadDir(staging)
				if err != nil || len(entries) != 0 {
					t.Fatal("signal left private query or expectation staging")
				}
				unchanged()
				row, err := json.Marshal(map[string]any{"phase": phase, "signal": signal.name,
					"observer_exit": exit.ExitCode(), "category": *report.Category, "checked_targets": report.CheckedTargets,
					"verifier_exit": report.Verifier.ExitCode, "consumer_exit": report.Consumer.ExitCode,
					"child_lifetime_released": true, "private_staging_empty": true, "input_unchanged": true})
				if err != nil {
					t.Fatal("cannot encode selected cancellation observation")
				}
				t.Logf("observer-signal-observation %s", row)
			})
		}
	}
}

func waitObserverSignalLock(dir string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		lock, err := statelock.Acquire(filepath.Join(dir, "child"))
		if err == nil {
			return lock.Close() == nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}
