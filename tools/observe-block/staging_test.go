package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestProcessFileCapturePreservesCompletion(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("cannot select process fixture")
	}
	t.Setenv("ZENON_OBSERVER_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	for _, mode := range []string{"success", "failed", "stdout limit", "stderr limit", "sleep", "inherited pipe"} {
		t.Run(mode, func(t *testing.T) {
			timeout := 5 * time.Second
			if mode == "sleep" {
				timeout = 100 * time.Millisecond
			}
			args := []string{"-test.run=^TestObservationProcessHelper$", "--", mode}
			buffered := runProcess(context.Background(), binary, args, 32, timeout)
			file, err := os.CreateTemp(t.TempDir(), "capture-")
			if err != nil {
				t.Fatal("cannot create private capture")
			}
			defer func() { _ = file.Close() }()
			staged := runProcessOutput(context.Background(), binary, args, 32, timeout, file)
			raw, err := os.ReadFile(file.Name())
			if err != nil || !bytes.Equal(raw, buffered.stdout) || len(raw) > 32 || len(staged.stdout) != 0 ||
				staged.category != buffered.category || staged.code != buffered.code ||
				staged.StdoutBytes != buffered.StdoutBytes || staged.StderrBytes != buffered.StderrBytes ||
				staged.ElapsedNS <= 0 || staged.ExitCode == nil || buffered.ExitCode == nil {
				t.Fatal("file capture changed joined completion, caps or separated streams")
			}
			if mode == "success" || mode == "failed" {
				if *staged.ExitCode != *buffered.ExitCode {
					t.Fatal("completed process lost its actual exit")
				}
			} else if mode == "sleep" && *staged.ExitCode == 0 {
				t.Fatal("timed-out process acquired success")
			}
			if bytes.Contains(raw, []byte("PRIVATE")) {
				t.Fatal("discarded diagnostics entered the staged output")
			}
		})
	}
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if cancelled {
			cancel()
		}
		var out bytes.Buffer
		r := runProcessOutput(ctx, filepath.Join(t.TempDir(), "PRIVATE_ABSENT"), nil, 32, time.Second, &out)
		cancel()
		category := "process_unavailable"
		if cancelled {
			category = "cancelled"
		}
		if r.category != category || r.ExitCode != nil || r.StdoutBytes != 0 || out.Len() != 0 {
			t.Fatal("unstarted process acquired completion or staged bytes")
		}
	}
}

func TestFileCaptureWriteFailureStopsAndJoinsLiveChild(t *testing.T) {
	t.Setenv("ZENON_OBSERVER_CONCURRENT_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("cannot select live process fixture")
	}
	file, err := os.CreateTemp(t.TempDir(), "closed-")
	if err != nil || file.Close() != nil {
		t.Fatal("cannot select closed destination")
	}
	for _, destination := range []io.Writer{file, shortWriter{}} {
		path := filepath.Join(t.TempDir(), "PRIVATE_CHILD_LOCK")
		ctx, cancel := context.WithCancel(context.Background())
		r := runProcessOutput(ctx, binary, []string{"-test.run=^TestConcurrentObservationProcessHelper$", "--", "success", path}, maxSummaryBytes, 10*time.Second, destination)
		if ctx.Err() != nil {
			t.Fatal("destination failure cancelled the caller")
		}
		cancel()
		if r.category != "input_unavailable" || r.code != 70 || r.ExitCode == nil || *r.ExitCode == 0 ||
			r.StdoutBytes != int64(len(concurrentProcessSummary)) || len(r.stdout) != 0 || r.ElapsedNS >= int64(9*time.Second) {
			t.Fatal("destination failure lost actual child completion or waited for timeout")
		}
		assertConcurrentHelperLock(t, path, false)
	}
}

func TestCollectedFileRefusesIncompleteOrUnavailableStaging(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("cannot select collector fixture")
	}
	t.Setenv("ZENON_OBSERVER_COLLECTION_TEST", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	c := configuration{timeout: 5 * time.Second, collection: collectionConfiguration{binary: binary}}
	for _, raw := range []string{"", "{", "{} {}", `{"data":"PRIVATE"}`, `null`, `[1,2]`, strings.Repeat("[", 10001) + strings.Repeat("]", 10001)} {
		t.Run(strconv.Itoa(len(raw))+"-"+strconv.FormatBool(json.Valid([]byte(raw))), func(t *testing.T) {
			t.Setenv("ZENON_OBSERVER_COLLECTION_OUTPUT", raw)
			dir := t.TempDir()
			path := filepath.Join(dir, "candidate.json")
			r := collectBundle(context.Background(), c, path)
			if r.ExitCode == nil || *r.ExitCode != 0 || r.StdoutBytes != int64(len(raw)) || len(r.stdout) != 0 {
				t.Fatal("completed collector lost its actual status or retained output")
			}
			category := "invalid_bundle"
			if json.Valid([]byte(raw)) {
				category = ""
			}
			if r.category != category {
				t.Fatal("staged syntax/depth boundary changed")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != raw {
				t.Fatal("staging changed completed collector bytes")
			}
			if info, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
				t.Fatal("private staging permissions changed")
			}
			// Reopen/rename after return checks handle closure on native Windows.
			if os.Rename(path, path+".closed") != nil {
				t.Fatal("staging handle remained open")
			}
		})
	}
	for _, directory := range []bool{false, true} {
		dir := t.TempDir()
		marker := filepath.Join(dir, "PRIVATE_STARTED")
		t.Setenv("ZENON_OBSERVER_COLLECTION_STARTED", marker)
		path := filepath.Join(dir, "occupied")
		if directory {
			err = os.Mkdir(path, 0o700)
		} else {
			err = os.WriteFile(path, []byte("PRIVATE_EXISTING"), 0o600)
		}
		if err != nil {
			t.Fatal("cannot select unavailable staging")
		}
		r := collectBundle(context.Background(), c, path)
		if r.category != "input_unavailable" || r.code != 70 || r.ExitCode != nil || r.StdoutBytes != 0 {
			t.Fatal("unavailable staging acquired process completion")
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("collector started before exclusive private staging existed")
		}
		if !directory {
			raw, err := os.ReadFile(path)
			if err != nil || string(raw) != "PRIVATE_EXISTING" {
				t.Fatal("exclusive staging replaced an existing file")
			}
		}
	}
}

func TestStagedJSONChecksExactCompletedSize(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "staged-")
	if err != nil {
		t.Fatal("cannot select staged bytes")
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString("{}\n"); err != nil {
		t.Fatal("cannot write staged bytes")
	}
	if valid, err := stagedJSON(file, 3); err != nil || !valid {
		t.Fatal("complete staged JSON refused")
	}
	for _, count := range []int64{-1, 0, 2, 4, verify.DefaultMaxBundleBytes + 1} {
		if valid, err := stagedJSON(file, count); err == nil || valid {
			t.Fatal("mismatched or over-budget staged size accepted")
		}
	}
	if file.Close() != nil {
		t.Fatal("cannot close staged bytes")
	}
	if valid, err := stagedJSON(file, 3); err == nil || valid {
		t.Fatal("closed staged input accepted")
	}
}
