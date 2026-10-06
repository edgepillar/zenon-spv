package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/statelock"
)

const concurrentProcessSummary = "{\"schema_version\":1,\"status\":\"matched\",\"category\":null,\"checked_targets\":1}\n"
const concurrentProcessDiagnostic = "PRIVATE_CHILD_DIAGNOSTIC\n"

// Retain the lock through actual helper exit. Reacquisition after runProcess
// returns checks OS release, rather than an earlier application marker.
var concurrentProcessLock *statelock.Lock

func TestConcurrentObservationProcessHelper(t *testing.T) {
	if os.Getenv("ZENON_OBSERVER_CONCURRENT_HELPER") != "1" {
		return
	}
	mode, path := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	lock, err := statelock.Acquire(path)
	if err != nil {
		os.Exit(71)
	}
	concurrentProcessLock = lock
	if _, err := io.WriteString(os.Stdout, concurrentProcessSummary); err != nil {
		os.Exit(71)
	}
	if _, err := io.WriteString(os.Stderr, concurrentProcessDiagnostic); err != nil ||
		os.WriteFile(path+".ready", []byte("ready\n"), 0o600) != nil {
		os.Exit(71)
	}
	// A release file gates real child execution without shell scripts, network
	// access, fixed startup sleeps or assuming the child has already started.
	deadline := time.Now().Add(time.Minute)
	for {
		if _, err := os.Stat(path + ".release"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			os.Exit(72)
		}
		time.Sleep(10 * time.Millisecond)
	}
	switch mode {
	case "success", "cancelled":
	case "stdout limit":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, 4096))
	case "stderr limit":
		_, _ = os.Stderr.Write(bytes.Repeat([]byte{'x'}, 32768))
	default:
		os.Exit(64)
	}
	runtime.KeepAlive(concurrentProcessLock)
	os.Exit(0)
}

func TestConcurrentObservationProcessCancellation(t *testing.T) {
	t.Setenv("ZENON_OBSERVER_CONCURRENT_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("cannot select native concurrent helper")
	}
	for _, limitMode := range []string{"stdout limit", "stderr limit"} {
		t.Run(limitMode, func(t *testing.T) {
			type invocation struct {
				path     string
				ctx      context.Context
				cancel   context.CancelFunc
				result   chan processResult
				consumed bool
			}
			children := make([]invocation, 4)
			dir := t.TempDir()
			// Cleanup releases even a deliberately broken cancellation fixture and
			// joins every owned runner before temporary files are removed.
			t.Cleanup(func() {
				for i := range children {
					child := &children[i]
					if child.cancel != nil {
						child.cancel()
						if os.WriteFile(child.path+".release", nil, 0o600) != nil {
							t.Error("cannot release owned helper during cleanup")
						}
					}
				}
				settlement := time.NewTimer(20 * time.Second)
				defer settlement.Stop()
				for i := range children {
					child := &children[i]
					if child.result != nil && !child.consumed {
						select {
						case <-child.result:
							child.consumed = true
						case <-settlement.C:
							t.Error("owned runner did not settle during cleanup")
							return
						}
					}
				}
			})
			for i, mode := range []string{"cancelled", limitMode, "success", "success"} {
				child := &children[i]
				child.path = filepath.Join(dir, []string{"cancelled", "limited", "first", "second"}[i])
				child.ctx, child.cancel = context.WithCancel(context.Background())
				child.result = make(chan processResult, 1)
				go func() {
					child.result <- runProcess(child.ctx, binary,
						[]string{"-test.run=^TestConcurrentObservationProcessHelper$", "--", mode, child.path},
						maxSummaryBytes, 30*time.Second)
				}()
			}
			readyDeadline := time.Now().Add(15 * time.Second)
			for i := range children {
				child := &children[i]
				for {
					if raw, err := os.ReadFile(child.path + ".ready"); err == nil && bytes.Equal(raw, []byte("ready\n")) {
						break
					}
					if time.Now().After(readyDeadline) {
						t.Fatal("concurrent helper never established active execution")
					}
					time.Sleep(10 * time.Millisecond)
				}
				assertConcurrentHelperLock(t, child.path, true)
			}
			take := func(index int) processResult {
				t.Helper()
				child := &children[index]
				timer := time.NewTimer(10 * time.Second)
				defer timer.Stop()
				select {
				case result := <-child.result:
					child.consumed = true
					assertConcurrentHelperLock(t, child.path, false)
					if result.ElapsedNS <= 0 || result.ExitCode == nil || bytes.Contains(result.stdout, []byte("PRIVATE")) {
						t.Fatal("actual child completion or diagnostic separation lost")
					}
					return result
				case <-timer.C:
					t.Fatal("active child did not settle before its own deadline")
					return processResult{}
				}
			}
			children[0].cancel()
			cancelled := take(0)
			if cancelled.category != "cancelled" || cancelled.code != 2 || *cancelled.ExitCode == 0 ||
				string(cancelled.stdout) != concurrentProcessSummary || cancelled.StdoutBytes != int64(len(concurrentProcessSummary)) ||
				cancelled.StderrBytes != int64(len(concurrentProcessDiagnostic)) {
				t.Fatal("active cancellation acquired successful completion or changed captured streams")
			}
			if matched, _, _ := matchSummary(cancelled.stdout, cancelled.ExitCode); matched {
				t.Fatal("cancelled child promoted its complete matched diagnostic")
			}
			if os.WriteFile(children[1].path+".release", nil, 0o600) != nil {
				t.Fatal("cannot release selected stream-limit helper")
			}
			limited := take(1)
			if limited.category != "output_limit" || limited.code != 2 || len(limited.stdout) > maxSummaryBytes || children[1].ctx.Err() != nil {
				t.Fatal("stream limit escaped its own invocation or acquired success")
			}
			if limitMode == "stdout limit" && (limited.StdoutBytes <= maxSummaryBytes || limited.StderrBytes != int64(len(concurrentProcessDiagnostic))) ||
				limitMode == "stderr limit" && (limited.StderrBytes <= 16<<10 || string(limited.stdout) != concurrentProcessSummary) {
				t.Fatal("violating stream lost its observed byte boundary")
			}
			// Mutating settled output must not change another invocation's buffer.
			cancelled.stdout[0] = '!'
			if len(limited.stdout) > 0 {
				limited.stdout[0] = '!'
			}
			for i := 2; i < len(children); i++ {
				child := &children[i]
				if child.ctx.Err() != nil {
					t.Fatal("one invocation cancelled an independent sibling context")
				}
				select {
				case <-child.result:
					child.consumed = true
					t.Fatal("independent sibling completed before explicit release")
				default:
				}
				assertConcurrentHelperLock(t, child.path, true)
				if os.WriteFile(child.path+".release", nil, 0o600) != nil {
					t.Fatal("cannot release independent sibling")
				}
				success := take(i)
				matched, category, count := matchSummary(success.stdout, success.ExitCode)
				if success.category != "" || success.code != 0 || *success.ExitCode != 0 || !matched || category != "" || count != 1 ||
					string(success.stdout) != concurrentProcessSummary || success.StdoutBytes != int64(len(concurrentProcessSummary)) ||
					success.StderrBytes != int64(len(concurrentProcessDiagnostic)) {
					t.Fatal("independent sibling lost its exact completed result")
				}
			}
		})
	}
}

func assertConcurrentHelperLock(t *testing.T, path string, busy bool) {
	t.Helper()
	lock, err := statelock.Acquire(path)
	if lock != nil {
		if lock.Close() != nil {
			t.Fatal("cannot release observed helper lifetime lock")
		}
	}
	if busy && !errors.Is(err, statelock.ErrBusy) || !busy && err != nil {
		t.Fatal("actual helper lifetime disagreed with observed process completion")
	}
}
