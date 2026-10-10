package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestObserverQueryStagingHelper(t *testing.T) {
	if os.Getenv("ZENON_QUERY_STAGING_HELPER") != "1" {
		return
	}
	args := os.Args
	n, err := strconv.Atoi(args[len(args)-2])
	if err != nil || n < 0 || n > maxReportBytes+1 {
		os.Exit(64)
	}
	chunk := bytes.Repeat([]byte{0x81}, 4096)
	for n > 0 {
		count := min(n, len(chunk))
		if wrote, err := os.Stdout.Write(chunk[:count]); err != nil || wrote != count {
			os.Exit(71)
		}
		n -= count
	}
	if args[len(args)-1] == "failed" {
		_, _ = io.WriteString(os.Stderr, "PRIVATE_QUERY_DIAGNOSTIC")
		os.Exit(70)
	}
	os.Exit(0)
}

type queryTestCloser struct {
	io.Writer
	closeError error
	closes     int
}

func (f *queryTestCloser) Close() error {
	f.closes++
	return f.closeError
}

func TestObserverQueryStagingContract(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("cannot select process fixture")
	}
	t.Setenv("ZENON_QUERY_STAGING_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	args := func(n int, mode string) []string {
		return []string{"-test.run=^TestObserverQueryStagingHelper$", "--", strconv.Itoa(n), mode}
	}
	check := func(t *testing.T, r processResult, category string, code int) {
		t.Helper()
		if r.category != category || r.code != code || len(r.stdout) != 0 {
			t.Fatal("query staging changed completion or retained report bytes")
		}
	}
	t.Run("complete_byte_boundaries", func(t *testing.T) {
		for _, n := range []int{0, 699, 55897, maxReportBytes} {
			path := filepath.Join(t.TempDir(), "query.json")
			// The historical buffered process reader is the independent baseline.
			baseline := runProcess(context.Background(), binary, args(n, "success"), maxReportBytes, 10*time.Second)
			r := stageQueryReport(context.Background(), binary, args(n, "success"), path, 10*time.Second)
			check(t, r, "", 0)
			raw, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, baseline.stdout) || !bytes.Equal(raw, bytes.Repeat([]byte{0x81}, n)) ||
				r.ExitCode == nil || *r.ExitCode != 0 || baseline.ExitCode == nil || *baseline.ExitCode != 0 ||
				r.StdoutBytes != int64(n) || r.StderrBytes != 0 || r.ElapsedNS <= 0 {
				t.Fatal("complete query capture changed raw bytes or actual child completion")
			}
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
				t.Fatal("query capture did not use a private regular file")
			}
			if os.Rename(path, path+".closed") != nil {
				t.Fatal("query file remained open after completed capture")
			}
		}
	})
	t.Run("oversize_and_failed_children", func(t *testing.T) {
		for _, mode := range []string{"oversize", "failed"} {
			n, outcome, category := maxReportBytes+1, "success", "output_limit"
			if mode == "failed" {
				n, outcome, category = 699, "failed", "process_failure"
			}
			path := filepath.Join(t.TempDir(), "query.json")
			r := stageQueryReport(context.Background(), binary, args(n, outcome), path, 10*time.Second)
			check(t, r, category, 2)
			raw, err := os.ReadFile(path)
			if err != nil || len(raw) > maxReportBytes || !bytes.Equal(raw, bytes.Repeat([]byte{0x81}, len(raw))) || r.ExitCode == nil {
				t.Fatal("failed query did not preserve bounded private bytes and completion")
			}
			if mode == "failed" && (*r.ExitCode != 70 || r.StdoutBytes != 699 || r.StderrBytes == 0) {
				t.Fatal("query process failure lost its actual exit or diagnostic count")
			}
			if os.Rename(path, path+".closed") != nil {
				t.Fatal("failed query capture retained a handle")
			}
		}
	})
	t.Run("exclusive_creation_before_child", func(t *testing.T) {
		for _, directory := range []bool{false, true} {
			path := filepath.Join(t.TempDir(), "occupied")
			if directory {
				err = os.Mkdir(path, 0o700)
			} else {
				err = os.WriteFile(path, []byte("PRIVATE_PRESERVE"), 0o600)
			}
			if err != nil {
				t.Fatal("cannot prepare occupied capture path")
			}
			r := stageQueryReport(context.Background(), binary, args(699, "success"), path, 10*time.Second)
			check(t, r, "input_unavailable", 70)
			if r.ExitCode != nil || r.StdoutBytes != 0 || r.ElapsedNS != 0 {
				t.Fatal("failed query creation started a child")
			}
			if !directory {
				raw, err := os.ReadFile(path)
				if err != nil || string(raw) != "PRIVATE_PRESERVE" {
					t.Fatal("occupied report file was changed")
				}
			}
		}
	})
	t.Run("close_failure_refuses_complete_report", func(t *testing.T) {
		for _, mode := range []string{"success", "failed"} {
			var raw bytes.Buffer
			file := &queryTestCloser{Writer: &raw, closeError: errors.New("PRIVATE_CLOSE_FAILURE")}
			r := stageQueryReportWithOpen(context.Background(), binary, args(699, mode), "unused", 10*time.Second,
				func(string) (io.WriteCloser, error) { return file, nil })
			category, code := "input_unavailable", 70
			if mode == "failed" {
				category, code = "process_failure", 2
			}
			check(t, r, category, code)
			if file.closes != 1 || raw.Len() != 699 || r.ExitCode == nil || (mode == "success" && *r.ExitCode != 0) {
				t.Fatal("close failure changed actual child exit or did not close exactly once")
			}
		}
	})
	t.Run("write_failure_stops_and_joins_child", func(t *testing.T) {
		t.Setenv("ZENON_OBSERVER_CONCURRENT_HELPER", "1")
		for _, short := range []bool{false, true} {
			path := filepath.Join(t.TempDir(), "PRIVATE_CHILD_LOCK")
			var destination io.Writer = shortWriter{}
			if !short {
				f, err := os.CreateTemp(t.TempDir(), "closed-")
				if err != nil || f.Close() != nil {
					t.Fatal("cannot prepare closed report destination")
				}
				destination = f
			}
			file := &queryTestCloser{Writer: destination}
			ctx, cancel := context.WithCancel(context.Background())
			r := stageQueryReportWithOpen(ctx, binary, []string{"-test.run=^TestConcurrentObservationProcessHelper$", "--", "success", path},
				"unused", 10*time.Second, func(string) (io.WriteCloser, error) { return file, nil })
			check(t, r, "input_unavailable", 70)
			if ctx.Err() != nil || file.closes != 1 || r.ExitCode == nil || *r.ExitCode == 0 || r.ElapsedNS >= int64(9*time.Second) {
				t.Fatal("failed report write did not stop and join the direct child")
			}
			cancel()
			assertConcurrentHelperLock(t, path, false)
		}
	})
	t.Run("unstarted_children_close_file", func(t *testing.T) {
		for _, cancelled := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			if cancelled {
				cancel()
			}
			file := &queryTestCloser{Writer: io.Discard}
			r := stageQueryReportWithOpen(ctx, filepath.Join(t.TempDir(), "PRIVATE_ABSENT"), nil, "unused", time.Second,
				func(string) (io.WriteCloser, error) { return file, nil })
			cancel()
			category, code := "process_unavailable", 70
			if cancelled {
				category, code = "cancelled", 2
			}
			check(t, r, category, code)
			if file.closes != 1 || r.ExitCode != nil || r.StdoutBytes != 0 {
				t.Fatal("unstarted query acquired completion or retained an open file")
			}
		}
	})
}
