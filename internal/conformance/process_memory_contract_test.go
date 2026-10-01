package conformance_test

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// This child is only a native accounting probe. Resource records still come
// from ordinary compiled zenon-spv consumers, not this test executable.
func TestProcessMemoryChild(t *testing.T) {
	args := flag.Args()
	if len(args) != 1 {
		return
	}
	switch args[0] {
	case "spv-memory-exit":
		os.Exit(0)
	case "spv-memory-fail":
		os.Exit(23)
	case "spv-memory-resident", "spv-memory-hold":
		resident := make([]byte, 32<<20)
		for i := 0; i < len(resident); i += 4096 {
			resident[i] = 1
		}
		if args[0] == "spv-memory-hold" {
			time.Sleep(10 * time.Minute)
		}
		runtime.KeepAlive(resident)
		os.Exit(0)
	}
}

func memoryChildCommand(t *testing.T, ctx context.Context, mode string) *exec.Cmd {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal("accounting test executable unavailable")
	}
	cmd := exec.CommandContext(ctx, path, "-test.run=^TestProcessMemoryChild$", "--", "spv-memory-"+mode)
	cmd.Env, cmd.WaitDelay = queryCLIEnvironment(), time.Second
	return cmd
}

func checkNativeMemorySample(t *testing.T, sample processMemorySample) {
	t.Helper()
	want := "unavailable"
	switch runtime.GOOS {
	case "linux", "darwin":
		want = "process_rusage"
	case "windows":
		want = "windows_peak_working_set"
	}
	if sample.source != want || (want == "unavailable" && sample.bytes != nil) ||
		(want != "unavailable" && (sample.bytes == nil || *sample.bytes == 0 || *sample.bytes > 1<<50)) {
		t.Fatal("missing or misidentified native process memory accounting")
	}
}

func TestProcessMemoryAccounting(t *testing.T) {
	for _, mode := range []string{"exit", "fail", "resident", "hold"} {
		t.Run(mode, func(t *testing.T) {
			timeout := 15 * time.Second
			if mode == "hold" {
				timeout = time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			cmd := memoryChildCommand(t, ctx, mode)
			sample, elapsed, err := runProcessWithMemory(cmd)
			checkNativeMemorySample(t, sample)
			if elapsed <= 0 || cmd.ProcessState == nil || (mode != "hold" && !cmd.ProcessState.Exited()) {
				t.Fatal("accounting lost child completion")
			}
			switch mode {
			case "exit", "resident":
				if err != nil || !cmd.ProcessState.Success() {
					t.Fatal("successful child failed")
				}
			case "fail":
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 23 {
					t.Fatal("nonzero child status changed")
				}
			case "hold":
				if err == nil || ctx.Err() != context.DeadlineExceeded || elapsed > 10*time.Second {
					t.Fatal("accounting prevented bounded cancellation")
				}
			}
			// Catch unit/current-counter substitution without prescribing a
			// precise peak or using these probe bytes as a consumer benchmark.
			if mode == "resident" && sample.bytes != nil && *sample.bytes < 8<<20 {
				t.Fatal("touched resident allocation absent from byte counter")
			}
		})
	}
	t.Run("start_failure", func(t *testing.T) {
		cmd := exec.Command(filepath.Join(t.TempDir(), "absent-accounting-child"))
		sample, _, err := runProcessWithMemory(cmd)
		if err == nil || sample.bytes != nil || sample.source != "unavailable" || cmd.Process != nil {
			t.Fatal("failed start fabricated a measurement")
		}
	})
}
