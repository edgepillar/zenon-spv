//go:build candidate_tree_import_scale && candidate_patch_tree_tail && candidate_retention && (darwin || linux)

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
)

// Literal files, never candidate Dump output. A 4096-record complete seed is
// split into four files; the unchanged importer still caps every file at 1024.
func importScaleChunks(item retentionInput, height int) [][]byte {
	count, start := 8, (height-2)*8%item.Keys
	if height == 1 {
		count, start = item.Keys, 0
	}
	chunks, raw := [][]byte{}, []byte{}
	for offset := 0; offset < count; offset++ {
		index := (start + offset) % item.Keys
		key := retentionKey(index)
		remove := height > 1 && height%3 == 0 && offset%3 == 0
		operation := byte(1)
		if remove {
			operation = 0
		}
		raw = append(raw, operation)
		raw = binary.AppendUvarint(raw, uint64(len(key)))
		raw = append(raw, key...)
		if !remove {
			amount := uint64(height*item.Keys + index + 1)
			if height > 1 && height%4 == 0 && offset == 1 {
				amount = 0
			}
			value := make([]byte, 32)
			binary.BigEndian.PutUint64(value[24:], amount)
			raw = append(raw, 32)
			raw = append(raw, value...)
		}
		if (offset+1)%1024 == 0 || offset+1 == count {
			chunks, raw = append(chunks, raw), []byte{}
		}
	}
	return chunks
}

const importScaleRSS = "getrusage(RUSAGE_SELF) after closed storage inventory and controlled final GC, before final conformance binding/output; includes setup, selected-map construction, conformance checks and GC"

func importScalePhysical(dir string) any {
	row := retentionPhysicalClosed(dir).(map[string]int64)
	allocated := int64(0)
	entries, err := os.ReadDir(dir)
	guardMust(err)
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(dir, entry.Name()))
		guardMust(err)
		st, ok := info.Sys().(*syscall.Stat_t)
		require(ok && st.Blocks >= 0, "unavailable owned file allocation")
		allocated += st.Blocks * 512
	}
	row["allocated_file_bytes"] = allocated
	return row
}

func TestTreeImportScaleChild(t *testing.T) {
	name, mode := os.Getenv("TREE_IMPORT_SCALE_CASE"), os.Getenv("TREE_IMPORT_SCALE_MODE")
	repetition, err := strconv.Atoi(os.Getenv("TREE_IMPORT_SCALE_REPETITION"))
	require(err == nil && repetition >= 0 && repetition < 3 && (mode == "plain" || mode == "allocation"), "unselected import scale sample")
	item := retentionInput{name, 0, 16, 8}
	switch name {
	case "import-512-16-retain8":
		item.Keys = 512
	case "import-4096-16-retain8":
		item.Keys = 4096
	default:
		t.Fatal("unselected import scale workload")
	}
	dir, target := t.TempDir(), map[string]string{}
	database := filepath.Join(dir, "database")
	// Prepare stable literal files before any storage operation. No resident raw
	// fixture is passed to importFileApply. File setup is outside phase timers.
	inputs := map[int][]importInput{}
	paths := map[string]string{}
	selected := map[int]map[string]string{0: {}}
	for height := 1; height <= item.Versions; height++ {
		state := map[string]string{}
		for k, v := range selected[height-1] {
			state[k] = v
		}
		start, count := (height-2)*8%item.Keys, 8
		if height == 1 {
			start, count = 0, item.Keys
		}
		for offset := 0; offset < count; offset++ {
			index := (start + offset) % item.Keys
			key := hex.EncodeToString(retentionKey(index))
			if height > 1 && height%3 == 0 && offset%3 == 0 {
				delete(state, key)
			} else {
				amount := uint64(height*item.Keys + index + 1)
				if height > 1 && height%4 == 0 && offset == 1 {
					amount = 0
				}
				value := make([]byte, 32)
				binary.BigEndian.PutUint64(value[24:], amount)
				state[key] = hex.EncodeToString(value)
			}
		}
		for chunk, raw := range importScaleChunks(item, height) {
			label := fmt.Sprintf("%s/%d/%d", name, height, chunk)
			records := count - chunk*1024
			if records > 1024 {
				records = 1024
			}
			require(len(raw) <= 1<<20 && records > 0 && records <= 1024, "literal input exceeds existing parser caps")
			input := importInput{decodeInput{label, nil}, importCeilings, importSelection{label, uint64(len(raw)), uint64(records), types.NewHash(raw).String()}, "none"}
			inputs[height] = append(inputs[height], input)
			path := filepath.Join(dir, fmt.Sprintf("input-%d-%d.raw", height, chunk))
			guardMust(os.WriteFile(path, raw, 0600))
			paths[label] = path
		}
		selected[height] = state
	}
	metrics := []any{}
	measure := func(label string, action func()) {
		var first, last runtime.MemStats
		if mode == "allocation" {
			runtime.ReadMemStats(&first)
		}
		start := time.Now()
		action()
		elapsed := time.Since(start).Nanoseconds()
		row := map[string]any{"phase": label, "elapsed_ns": elapsed, "go_total_alloc_delta_bytes": nil, "go_mallocs_delta": nil, "go_gc_cycles": nil}
		if mode == "allocation" {
			runtime.ReadMemStats(&last)
			row["go_total_alloc_delta_bytes"], row["go_mallocs_delta"], row["go_gc_cycles"] = last.TotalAlloc-first.TotalAlloc, last.Mallocs-first.Mallocs, uint64(last.NumGC-first.NumGC)
		}
		metrics = append(metrics, row)
	}
	runtime.GC()
	var ldb *leveldb.DB
	var tree *trie.NodeTree
	measure("open", func() { ldb, tree = retentionOpen(database) })
	closed := false
	defer func() {
		if !closed {
			guardMust(ldb.Close())
		}
	}()
	steps := []any{}
	for height := 1; height <= item.Versions; height++ {
		// Select the complete intended map/root from literal inputs, independently
		// of the imported map and database. The Python oracle rederives all bytes.
		wanted, reason := treePreflight(selected[height], types.ZeroHash)
		require(reason == "selected_root_mismatch", "unselected empty history")
		beforeHeight := target
		imports := []any{}
		for _, input := range inputs[height] {
			file, err := os.Open(paths[input.name])
			guardMust(err)
			_, err = file.Seek(7, io.SeekStart)
			guardMust(err)
			before := targetSummary(target)
			borrowed := target
			var result importFileExecution
			measure(input.name+"/file-import", func() { result = importFileApply(file, input, target, importTargetCeilings) })
			require(result.refusal == "", "selected file import refused")
			cursor, err := file.Seek(0, io.SeekCurrent)
			guardMust(err)
			guardMust(file.Close())
			raw, err := os.ReadFile(paths[input.name])
			guardMust(err)
			require(cursor == 7 && uint64(len(raw)) == input.selection.Bytes && types.NewHash(raw).String() == input.selection.ChangesHash, "file or descriptor changed")
			require(bytes.Equal(resourceJSON(before), resourceJSON(targetSummary(borrowed))), "borrowed map changed")
			imports = append(imports, map[string]any{"selection": input.selection, "raw_sha256": resourceHash(raw), "before": before, "after": targetSummary(result.target), "callbacks": resourceCallbacks(result.stage.events), "source_cursor_preserved": true, "original_alias_preserved": true,
				"stat_calls": result.statCalls, "read_calls": result.readCalls, "buffer_bytes": result.bufferBytes, "read_bytes": result.readBytes, "preflight_records": len(result.stage.expected), "raw_copies": result.rawCopies, "constructor_calls": result.constructorCalls, "replay_calls": result.replayCalls, "clone_calls": result.cloneCalls, "cloned_entries": result.clonedEntries, "replacements": result.replacements})
			target = result.target
		}
		prefix := fmt.Sprintf("%d/", height)
		var actual types.Hash
		measure(prefix+"complete-map-root-preflight", func() { actual, reason = treePreflight(target, wanted) })
		require(reason == "", "complete imported map root differs")
		events := []importEvent{}
		measure(prefix+"delta-and-Update", func() { guardMust(tree.Update(tailDelta(beforeHeight, target, &events))) })
		measure(prefix+"Commit", func() {
			if height == 1 {
				guardMust(tree.CommitBulk(retentionIdentifier(item.Keys, height)))
			} else {
				guardMust(tree.Commit(retentionIdentifier(item.Keys, height)))
			}
		})
		if height > item.Retain {
			measure(prefix+"Prune", func() { guardMust(tree.Prune(uint64(height - item.Retain + 1))) })
		}
		steps = append(steps, map[string]any{"height": height, "imports": imports, "complete_map": targetSummary(target), "selected_root": wanted.String(), "preflight_root": actual.String(), "delta_callbacks": resourceCallbacks(events)})
	}
	// Independently bind full logical storage and actual roots/proofs in all three
	// rounds using unchanged observers; query API sums are separate measurements.
	rounds, queries, physical := []any{}, []any{}, []any{}
	row, timing := retentionObserve(tree, ldb, item, 0)
	rounds, queries = append(rounds, row), append(queries, timing)
	measure("clean-close", func() { guardMust(ldb.Close()); closed = true })
	physical = append(physical, importScalePhysical(database))
	measure("clean-reopen", func() { ldb, tree = retentionOpen(database); closed = false })
	row, timing = retentionObserve(tree, ldb, item, 1)
	rounds, queries = append(rounds, row), append(queries, timing)
	measure("compact", func() { guardMust(ldb.CompactRange(util.Range{})) })
	measure("compact-close", func() { guardMust(ldb.Close()); closed = true })
	physical = append(physical, importScalePhysical(database))
	measure("compact-reopen", func() { ldb, tree = retentionOpen(database); closed = false })
	row, timing = retentionObserve(tree, ldb, item, 2)
	rounds, queries = append(rounds, row), append(queries, timing)
	measure("final-close", func() { guardMust(ldb.Close()); closed = true })
	physical = append(physical, importScalePhysical(database))
	// This controlled post-GC HeapAlloc snapshot includes the explicitly live
	// selected maps, import metadata, final map, conformance and closed tree.
	runtime.GC()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	var usage syscall.Rusage
	guardMust(syscall.Getrusage(syscall.RUSAGE_SELF, &usage))
	peak := usage.Maxrss
	if runtime.GOOS == "linux" {
		peak *= 1024
	}
	conformance := map[string]any{"input": item, "steps": steps, "rounds": rounds, "bulk_commits": 1, "tail_commits": item.Versions - 1, "prune_calls": item.Versions - item.Retain, "consumer_result": "REFUSED"}
	measurement := map[string]any{"case": name, "mode": mode, "repetition": repetition, "go_version": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH, "conformance_sha256": resourceHash(resourceJSON(conformance)), "phase_resources": metrics, "query_timings": queries, "closed_storage": physical, "process_peak_rss_bytes": peak, "process_peak_rss_method": importScaleRSS, "post_gc_heap_alloc_bytes": memory.HeapAlloc,
		"post_gc_heap_method": "runtime.GC then ReadMemStats HeapAlloc; selected maps, final map, conformance, input metadata and closed tree explicitly live; before final result binding/output", "whole_pipeline_time_measured": false, "whole_pipeline_memory_measured": false, "peak_disk_measured": false}
	runtime.KeepAlive(selected)
	runtime.KeepAlive(target)
	runtime.KeepAlive(inputs)
	runtime.KeepAlive(paths)
	runtime.KeepAlive(tree)
	runtime.KeepAlive(steps)
	runtime.KeepAlive(rounds)
	fmt.Println("TREE_IMPORT_SCALE=" + string(resourceJSON(map[string]any{"conformance": conformance, "measurement": measurement})))
}
