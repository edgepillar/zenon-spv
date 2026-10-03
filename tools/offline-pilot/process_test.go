package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/statelock"
)

const pilotHelperEnvironment = "SPV_PILOT_PROCESS_HELPER"

// Keep the lock reachable until process termination, including after the last
// local KeepAlive call, so only actual OS process release settles the holder.
var pilotHelperOwnedLock *statelock.Lock

// Helpers emit a fixed event fixture, never run Go, and use no shell/network.
// An inherited-stdout holder has a finite lifetime and an OS-released private
// lock. The owning test waits for lock release before removing helper files;
// this is fixture settlement, not production process-tree supervision.
func TestPilotProcessHelper(t *testing.T) {
	if os.Getenv(pilotHelperEnvironment) != "1" {
		return
	}
	mode, path := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	if mode == "hold stdout" {
		lock, err := statelock.Acquire(path)
		if err != nil || os.WriteFile(path+".ready", []byte("ready\n"), 0o600) != nil {
			os.Exit(71)
		}
		pilotHelperOwnedLock = lock
		time.Sleep(4 * time.Second)
		runtime.KeepAlive(pilotHelperOwnedLock)
		// Deliberately retain the lock until exit, so reacquisition establishes
		// actual OS release instead of merely an earlier completion marker.
		os.Exit(0)
	}
	if mode == "retained stdout exit" || mode == "retained stdout cancellation" {
		self, err := os.Executable()
		if err != nil {
			os.Exit(71)
		}
		child := exec.Command(self, "-test.run=^TestPilotProcessHelper$", "--", "hold stdout", path)
		child.Stdout, child.Env = os.Stdout, os.Environ()
		if child.Start() != nil || !pilotHelperReady(path, 3*time.Second) {
			os.Exit(71)
		}
		_ = child.Process.Release()
	}
	if mode == "malformed stream" || mode == "collector rejection during flood" {
		// The invalid first line rejects the collector. A larger-than-pipe
		// flood then blocks command copying on the now-unread io.Pipe.Writer,
		// exercising the reader closure needed to join that copying goroutine.
		guard := time.AfterFunc(3*time.Second, func() { os.Exit(72) })
		flood := append([]byte("PRIVATE_PATH NOT_JSON\n"), bytes.Repeat([]byte{'x'}, 1<<20)...)
		_, _ = os.Stdout.Write(flood)
		guard.Stop()
		os.Exit(0)
	}
	encoder := json.NewEncoder(os.Stdout)
	events := sampleEvents()
	for _, event := range events[:len(events)-2] {
		if encoder.Encode(event) != nil {
			os.Exit(71)
		}
	}
	// Fill more than a pipe buffer before the final root/package completions.
	// They must survive ordinary exit and be consumed before copy closure.
	for range 32 {
		if encoder.Encode(testEvent{Action: "output", Package: events[1].Package,
			Test: events[1].Test, Output: strings.Repeat("x", 8192)}) != nil {
			os.Exit(71)
		}
	}
	for _, event := range events[len(events)-2:] {
		if encoder.Encode(event) != nil {
			os.Exit(71)
		}
	}
	switch mode {
	case "complete", "retained stdout exit":
		os.Exit(0)
	case "failed after complete events":
		os.Exit(70)
	case "deadline after complete events":
		time.Sleep(3 * time.Second)
		os.Exit(0)
	case "retained stdout cancellation":
		time.Sleep(8 * time.Second)
		os.Exit(0)
	default:
		os.Exit(64)
	}
}

func pilotHelperReady(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(path + ".ready"); err == nil && bytes.Equal(raw, []byte("ready\n")) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func settlePilotHelper(t *testing.T, path string) {
	t.Helper()
	if !pilotHelperReady(path, 4*time.Second) {
		t.Error("owned stdout holder never established its private lifetime")
		return
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		lock, err := statelock.Acquire(path)
		if err == nil {
			if lock.Close() != nil {
				t.Error("cannot release settled helper lock")
			}
			return
		}
		if !errors.Is(err, statelock.ErrBusy) {
			t.Error("cannot inspect owned helper lifetime")
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("owned stdout holder did not terminate within its finite lifetime")
}

func TestPilotProcessBoundaries(t *testing.T) {
	t.Setenv(pilotHelperEnvironment, "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	self, err := os.Executable()
	if err != nil {
		t.Fatal("cannot identify native helper binary")
	}
	for _, tc := range []struct {
		name, category string
		holder, cancel bool
	}{
		{"complete", "", false, false},
		{"retained stdout exit", "test_process", true, false},
		{"retained stdout cancellation", "test_timeout", true, true},
		{"malformed stream", "test_stream", false, false},
		{"collector rejection during flood", "test_stream", false, false},
		{"failed after complete events", "test_process", false, false},
		{"deadline after complete events", "test_timeout", false, false},
		{"failed start", "test_start", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "PRIVATE_HELPER_LIFETIME")
			if tc.holder {
				t.Cleanup(func() { settlePilotHelper(t, path) })
			}
			timeout := 8 * time.Second
			if tc.name == "deadline after complete events" {
				timeout = 500 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			cancelled := make(chan bool, 1)
			if tc.cancel {
				go func() {
					ready := pilotHelperReady(path, 3*time.Second)
					if ready {
						time.Sleep(100 * time.Millisecond)
					}
					cancel()
					cancelled <- ready
				}()
			}
			binary := self
			if tc.name == "failed start" {
				binary = filepath.Join(filepath.Dir(path), "PRIVATE_MISSING_BINARY")
			}
			collector := newCollector(sampleManifest())
			readEvents := collector.read
			rejectedAfterFirstByte := false
			if tc.name == "collector rejection during flood" {
				readEvents = func(reader io.Reader) error {
					var first [1]byte
					if _, err := io.ReadFull(reader, first[:]); err != nil {
						return err
					}
					if first[0] != 'P' {
						return errors.New("unexpected helper stream byte")
					}
					rejectedAfterFirstByte = true
					// One byte leaves the command's larger io.Pipe.Write pending.
					// Rejecting must close the reader before waiting for that copy.
					return errors.New("rejected test event stream")
				}
			}
			complete, category := runTestProcess(ctx, binary,
				[]string{"-test.run=^TestPilotProcessHelper$", "--", tc.name, path}, os.Environ(), readEvents)
			if tc.name == "collector rejection during flood" && !rejectedAfterFirstByte {
				t.Fatal("transport fixture never established rejection after its first byte")
			}
			if tc.cancel && !<-cancelled {
				t.Fatal("cancelled fixture never established inherited stdout")
			}
			if (category == nil) != (tc.category == "") || complete != (tc.category == "") ||
				category != nil && (*category != tc.category || strings.Contains(*category, "PRIVATE")) {
				t.Fatal("native process/stream outcome lost its fixed category")
			}
			if tc.category == "" {
				if collector.finish(complete) != "passed" || collector.cases[0].Passed != 1 || len(collector.cases[0].Binaries) != 1 {
					t.Fatal("ordinary exit truncated trailing completion or executable records")
				}
			} else if collector.finish(complete) == "passed" {
				t.Fatal("failed process or stream acquired a successful report")
			}
			if tc.holder {
				lock, lockErr := statelock.Acquire(path)
				if lock != nil || !errors.Is(lockErr, statelock.ErrBusy) {
					_ = lock.Close()
					t.Fatal("runner waited for inherited stdout holder lifetime instead of its own settlement limit")
				}
			}
		})
	}
}
