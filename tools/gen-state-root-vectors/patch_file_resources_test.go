//go:build candidate_patch_file_resources && (darwin || linux)

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

const fileResourcePeakMethod = "getrusage(RUSAGE_SELF) after importFileApply and stats sampling, before output binding; process lifetime high water includes startup, fixture creation, file open, initial binding and pre-operation GC"

func fileResourceFamilies() []string {
	return append(patchResourceFamilies(), "file-wrong-byte-count", "file-over-raw-cap", "file-selection-over-cap")
}

func fileResourceInput(name string) patchResourceInput {
	switch name {
	case "file-wrong-byte-count", "file-over-raw-cap", "file-selection-over-cap":
		item := patchResourceInputFor("records-256-owned-1024")
		item.input.name, item.input.selection.Name = name, name
		switch name {
		case "file-wrong-byte-count":
			item.input.selection.Bytes--
		case "file-over-raw-cap":
			item.input.raw = make([]byte, (1<<20)+1)
		case "file-selection-over-cap":
			item.input.selection.Bytes = (1 << 20) + 1
		}
		return item
	default:
		return patchResourceInputFor(name)
	}
}

// One test process performs exactly one selected operation. Fixture construction,
// opening a read-only descriptor, independent selection and initial map bindings
// precede the timer. Output bindings, cleanup and serialization follow RSS.
func TestFileResourceChild(t *testing.T) {
	name, mode := os.Getenv("FILE_RESOURCE_CASE"), os.Getenv("FILE_RESOURCE_MODE")
	repetition, err := strconv.Atoi(os.Getenv("FILE_RESOURCE_REPETITION"))
	selected := false
	for _, candidate := range fileResourceFamilies() {
		selected = selected || candidate == name
	}
	if !selected || err != nil || repetition < 0 || repetition >= 3 || (mode != "plain" && mode != "allocation") {
		t.Fatal("unselected file resource child")
	}
	item := fileResourceInput(name)
	before, rawSize, rawHash := targetSummary(item.target), len(item.input.raw), resourceHash(item.input.raw)
	path := filepath.Join(t.TempDir(), "owned.raw")
	if err := os.WriteFile(path, item.input.raw, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	// The handoff obtains raw bytes from the descriptor. It receives no resident
	// raw fixture. Construction may still contribute to process lifetime RSS.
	item.input.raw = nil
	runtime.GC()
	var first, last runtime.MemStats
	if mode == "allocation" {
		runtime.ReadMemStats(&first)
	}
	start := time.Now()
	result := importFileApply(file, item.input, item.target, item.caps)
	elapsed := time.Since(start).Nanoseconds()
	if mode == "allocation" {
		runtime.ReadMemStats(&last)
	}
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	peak := usage.Maxrss
	if runtime.GOOS == "linux" {
		peak *= 1024
	}
	// All complete output checks are outside timing/allocation/RSS sampling.
	cursor, err := file.Seek(0, io.SeekCurrent)
	if err != nil || cursor != 7 {
		t.Fatal("borrowed descriptor cursor or lifetime changed")
	}
	after, err := os.ReadFile(path)
	if err != nil || len(after) != rawSize || resourceHash(after) != rawHash {
		t.Fatal("fixture bytes changed")
	}
	if string(resourceJSON(before)) != string(resourceJSON(targetSummary(item.target))) {
		t.Fatal("original map alias changed")
	}
	verdict := "STAGED"
	if result.refusal != "" {
		verdict = "REJECTED"
	}
	conformance := map[string]any{
		"name": name, "source_fault": "none", "import_fault": item.input.fault,
		"limits": item.input.limits, "selection": item.input.selection, "target_limits": item.caps,
		"file_before_bytes": rawSize, "file_before_sha256": rawHash,
		"file_after_bytes": len(after), "file_after_sha256": resourceHash(after),
		"file_stat_calls": result.statCalls, "file_read_calls": result.readCalls,
		"file_buffer_bytes": result.bufferBytes, "file_read_bytes": result.readBytes,
		"source_cursor_available": true, "source_cursor_preserved": true,
		"preflight_records": len(result.stage.expected), "raw_copies": result.rawCopies,
		"constructor_calls": result.constructorCalls, "default_replay_calls": result.replayCalls,
		"target_clone_calls": result.cloneCalls, "target_cloned_entries": result.clonedEntries,
		"staging_callbacks": resourceCallbacks(result.stage.events), "staging_target": targetSummary(result.stage.state),
		"target_before": before, "target_after": targetSummary(result.target), "original_alias_after": targetSummary(item.target),
		"target_replacements": result.replacements, "research_import_result": verdict,
		"refusal": result.refusal, "consumer_result": "REFUSED",
	}
	measurement := map[string]any{
		"case": name, "mode": mode, "repetition": repetition, "elapsed_ns": elapsed,
		"go_total_alloc_delta_bytes": nil, "go_mallocs_delta": nil, "go_gc_cycles": nil,
		"process_peak_rss_bytes": peak, "process_peak_rss_method": fileResourcePeakMethod,
		"conformance_sha256": resourceHash(resourceJSON(conformance)),
		"platform":           runtime.GOOS + "/" + runtime.GOARCH, "go_version": runtime.Version(),
	}
	if mode == "allocation" {
		measurement["go_total_alloc_delta_bytes"] = last.TotalAlloc - first.TotalAlloc
		measurement["go_mallocs_delta"] = last.Mallocs - first.Mallocs
		measurement["go_gc_cycles"] = uint64(last.NumGC - first.NumGC)
	}
	runtime.KeepAlive(item)
	runtime.KeepAlive(file)
	runtime.KeepAlive(result)
	runtime.KeepAlive(before)
	fmt.Println("PATCH_FILE_RESOURCE=" + string(resourceJSON(map[string]any{"conformance": conformance, "measurement": measurement})))
}
