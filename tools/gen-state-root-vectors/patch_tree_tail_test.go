//go:build candidate_patch_tree_tail && candidate_patch_tree && (darwin || linux)

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
	"sort"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
)

func tailFamilies() []string {
	return []string{"retained-8", "retained-32", "empty-transitions", "tail-selection-refusal", "tail-cap-refusal", "tail-key-refusal", "tail-value-refusal", "tail-root-refusal"}
}

func tailSeedSize(name string) int {
	if name == "empty-transitions" {
		return 0
	}
	if name == "retained-32" {
		return 32
	}
	return 8
}

// Complete intended maps are chosen from literal rules before reading a file.
// These selections are synthetic and never authenticate a network snapshot.
func tailSelected(name string, height int) map[int][]byte {
	state := treeComplete(tailSeedSize(name))
	if height == 3 {
		return state
	}
	if name == "empty-transitions" {
		if height == 4 {
			return map[int][]byte{0: guardValue(0), 1: guardValue(3)}
		}
		if height == 5 {
			return map[int][]byte{}
		}
		return map[int][]byte{0: guardValue(0), 3: guardValue(7)}
	}
	delete(state, 2)
	state[1], state[6], state[tailSeedSize(name)] = guardValue(0), guardValue(0), guardValue(10)
	if height >= 5 {
		delete(state, 0)
		if name == "tail-cap-refusal" {
			state[9] = guardValue(12)
		} else {
			state[2] = guardValue(12)
		}
	}
	return state
}

type tailEvent struct {
	operation  string
	key, value []byte
}

func tailEvents(name string, height int) []tailEvent {
	p := func(i int, value uint64) tailEvent { return tailEvent{"Put", guardKey(i), guardValue(value)} }
	d := func(i int) tailEvent { return tailEvent{"Delete", guardKey(i), nil} }
	if height == 3 {
		out := []tailEvent{}
		for i := 0; i < tailSeedSize(name); i++ {
			value := uint64(i + 1)
			if i == 0 {
				value = 0
			}
			out = append(out, p(i, value))
		}
		return out
	}
	if name == "empty-transitions" {
		if height == 4 {
			return []tailEvent{p(0, 0), p(1, 2), p(1, 3)}
		}
		if height == 5 {
			return []tailEvent{d(0), d(1)}
		}
		return []tailEvent{p(0, 0), p(3, 7)}
	}
	if height == 4 {
		n := tailSeedSize(name)
		return []tailEvent{d(2), p(1, 0), p(n, 9), p(n, 10), d(6), p(6, 0)}
	}
	if height == 6 {
		return []tailEvent{}
	}
	if name == "tail-cap-refusal" {
		return []tailEvent{p(9, 12), d(0)}
	}
	if name == "tail-key-refusal" {
		event := p(9, 12)
		event.key[21] = 5
		return []tailEvent{event}
	}
	if name == "tail-value-refusal" {
		return []tailEvent{{"Put", guardKey(9), []byte{}}}
	}
	return []tailEvent{d(0), p(2, 12)}
}

func tailInput(name string, height int, target map[string]string) patchResourceInput {
	raw := []byte{}
	events := tailEvents(name, height)
	for _, event := range events {
		operation := byte(0)
		if event.operation == "Put" {
			operation = 1
		}
		raw = append(raw, operation)
		raw = binary.AppendUvarint(raw, uint64(len(event.key)))
		raw = append(raw, event.key...)
		if operation == 1 {
			raw = binary.AppendUvarint(raw, uint64(len(event.value)))
			raw = append(raw, event.value...)
		}
	}
	label := fmt.Sprintf("%s/%d", name, height)
	selection := importSelection{label, uint64(len(raw)), uint64(len(events)), types.NewHash(raw).String()}
	caps := importTargetCeilings
	if height == 5 && name == "tail-selection-refusal" {
		selection.Records++
	}
	if height == 5 && name == "tail-cap-refusal" {
		caps = importTargetLimits{8, 1024}
	}
	return patchResourceInput{importInput{decodeInput{label, raw}, importCeilings, selection, "none"}, target, caps}
}

// Deltas explicitly delete keys absent from the selected complete next map.
// Reusing treeSeed on existing storage would leave those old leaves present.
func tailDelta(before, after map[string]string, events *[]importEvent) db.Patch {
	keys := map[string]bool{}
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	ordered := []string{}
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	patch := db.NewPatch()
	for _, key := range ordered {
		value, exists := after[key]
		previous, present := before[key]
		if exists && present && previous == value {
			continue
		}
		raw, err := hex.DecodeString(key)
		guardMust(err)
		if !exists {
			patch.Delete(raw)
		} else {
			decoded, err := hex.DecodeString(value)
			guardMust(err)
			patch.Put(raw, decoded)
		}
	}
	return &treeRecordedPatch{patch, events}
}

func tailObserve(name, label string, tree *trie.NodeTree, ldb *leveldb.DB) any {
	rows := []any{}
	for _, height := range []int{0, 1, 3, 4, 5, 6, 7} {
		id := guardIdentifier(name, height)
		root, err := tree.Root(id)
		rows = append(rows, map[string]any{"identifier": guardIDRecord(id), "key": nil, "root": root.String(), "value": nil, "proof": nil, "error": guardNullableError(err)})
		for _, index := range []int{0, 1, 2, 6, 8, 31, 32} {
			key := guardKey(index)
			value, proof, failure := tree.Prove(id, key)
			rows = append(rows, map[string]any{"identifier": guardIDRecord(id), "key": hex.EncodeToString(key), "root": nil, "value": guardNullableBytes(value), "proof": guardNullableBytes(proof), "error": guardNullableError(failure)})
		}
	}
	return map[string]any{"label": label, "frontier": guardIDRecord(tree.FrontierIdentifier()), "storage": guardStorage(ldb), "reads": rows}
}

func TestPatchTreeTailChild(t *testing.T) {
	name, mode := os.Getenv("PATCH_TREE_TAIL_CASE"), os.Getenv("PATCH_TREE_TAIL_MODE")
	repetition, err := strconv.Atoi(os.Getenv("PATCH_TREE_TAIL_REPETITION"))
	selected := false
	for _, family := range tailFamilies() {
		selected = selected || name == family
	}
	if !selected || err != nil || repetition < 0 || repetition >= 3 || (mode != "plain" && mode != "allocation") {
		t.Fatal("unselected tree tail child")
	}
	rootDir := t.TempDir()
	database := filepath.Join(rootDir, "tree")
	metrics := []any{}
	measure := func(label string, action func()) {
		var first, last runtime.MemStats
		if mode == "allocation" {
			runtime.ReadMemStats(&first)
		}
		start := time.Now()
		action()
		elapsed := time.Since(start).Nanoseconds()
		if mode == "allocation" {
			runtime.ReadMemStats(&last)
		}
		row := map[string]any{"phase": label, "elapsed_ns": elapsed, "go_total_alloc_delta_bytes": nil, "go_mallocs_delta": nil, "go_gc_cycles": nil}
		if mode == "allocation" {
			row["go_total_alloc_delta_bytes"], row["go_mallocs_delta"], row["go_gc_cycles"] = last.TotalAlloc-first.TotalAlloc, last.Mallocs-first.Mallocs, uint64(last.NumGC-first.NumGC)
		}
		metrics = append(metrics, row)
	}
	aliases := []map[string]string{}
	aliasBefore := []any{}
	files := []*os.File{}
	defer func() {
		for _, file := range files {
			guardMust(file.Close())
		}
	}()
	target := map[string]string{}
	rows, snapshots := []any{}, []any{}
	var ldb *leveldb.DB
	var tree *trie.NodeTree
	defer func() {
		if ldb != nil {
			guardMust(ldb.Close())
		}
	}()
	openCalls, updateCalls, bulkCalls, commitCalls, pruneCalls, reopenCalls := 0, 0, 0, 0, 0, 0
	runtime.GC()
	for height := 3; height <= 6; height++ {
		wanted, wantedMap := guardSelectedRoot(tailSelected(name, height))
		if height == 5 && name == "tail-root-refusal" {
			wanted = types.ZeroHash
		}
		item := tailInput(name, height, target)
		before, rawSize, rawHash := targetSummary(target), len(item.input.raw), resourceHash(item.input.raw)
		aliases = append(aliases, target)
		aliasBefore = append(aliasBefore, before)
		path := filepath.Join(rootDir, fmt.Sprintf("owned-%d.raw", height))
		guardMust(os.WriteFile(path, item.input.raw, 0600))
		file, err := os.Open(path)
		guardMust(err)
		files = append(files, file)
		_, err = file.Seek(7, io.SeekStart)
		guardMust(err)
		item.input.raw = nil
		prefix := fmt.Sprintf("%d/", height)
		var result importFileExecution
		measure(prefix+"opened-file-to-owned-map", func() { result = importFileApply(file, item.input, target, item.caps) })
		refusal := ""
		var observedRoot any
		if result.refusal != "" {
			refusal = "import_" + result.refusal
		} else {
			measure(prefix+"complete-balance-map-and-root-selection", func() {
				actual, reason := treePreflight(result.target, wanted)
				refusal = reason
				if reason != "unsupported_balance_key" && reason != "unsupported_balance_value" {
					observedRoot = actual.String()
				}
			})
		}
		events := []importEvent{}
		if refusal == "" {
			if height == 3 {
				measure("open-fresh-NodeTree", func() { ldb, tree = guardOpen(database); openCalls++ })
				snapshots = append(snapshots, tailObserve(name, "fresh", tree, ldb))
			}
			measure(prefix+"complete-map-delta-and-Update", func() { guardMust(tree.Update(tailDelta(target, result.target, &events))); updateCalls++ })
			snapshots = append(snapshots, tailObserve(name, fmt.Sprintf("staged-%d", height), tree, ldb))
			if height == 3 {
				measure("CommitBulk", func() { guardMust(tree.CommitBulk(guardIdentifier(name, height))); bulkCalls++ })
			} else {
				measure(prefix+"Commit", func() { guardMust(tree.Commit(guardIdentifier(name, height))); commitCalls++ })
			}
			target = result.target
			snapshots = append(snapshots, tailObserve(name, fmt.Sprintf("committed-%d", height), tree, ldb))
		} else {
			require(height == 5 && tree != nil, "unexpected seed or tail refusal")
			snapshots = append(snapshots, tailObserve(name, "refused-5", tree, ldb))
		}
		cursor, err := file.Seek(0, io.SeekCurrent)
		guardMust(err)
		after, err := os.ReadFile(path)
		guardMust(err)
		require(cursor == 7 && len(after) == rawSize && resourceHash(after) == rawHash && bytes.Equal(resourceJSON(before), resourceJSON(targetSummary(item.target))), "source or original tail alias changed")
		importVerdict, handoff := "STAGED", "COMMITTED_RESEARCH"
		if result.refusal != "" {
			importVerdict = "REJECTED"
		}
		if refusal != "" {
			handoff = "REJECTED"
		}
		imported := map[string]any{"name": item.input.name, "source_fault": "none", "import_fault": "none", "limits": item.input.limits, "selection": item.input.selection, "target_limits": item.caps,
			"file_before_bytes": rawSize, "file_before_sha256": rawHash, "file_after_bytes": len(after), "file_after_sha256": resourceHash(after), "file_stat_calls": result.statCalls, "file_read_calls": result.readCalls, "file_buffer_bytes": result.bufferBytes, "file_read_bytes": result.readBytes,
			"source_cursor_available": true, "source_cursor_preserved": true, "preflight_records": len(result.stage.expected), "raw_copies": result.rawCopies, "constructor_calls": result.constructorCalls, "default_replay_calls": result.replayCalls, "target_clone_calls": result.cloneCalls, "target_cloned_entries": result.clonedEntries,
			"staging_callbacks": resourceCallbacks(result.stage.events), "staging_target": targetSummary(result.stage.state), "target_before": before, "target_after": targetSummary(result.target), "original_alias_after": targetSummary(item.target), "target_replacements": result.replacements, "research_import_result": importVerdict, "refusal": result.refusal, "consumer_result": "REFUSED"}
		rows = append(rows, map[string]any{"height": height, "import": imported, "selected_complete_map": wantedMap, "selected_root": wanted.String(), "preflight_root": observedRoot, "handoff_refusal": refusal, "tree_staging_callbacks": resourceCallbacks(events), "research_handoff_result": handoff, "consumer_result": "REFUSED"})
		if refusal != "" {
			break
		}
	}
	if len(rows) == 4 {
		measure("Prune/5", func() { guardMust(tree.Prune(5)); pruneCalls++ })
		snapshots = append(snapshots, tailObserve(name, "pruned-5", tree, ldb))
	}
	measure("clean-close", func() { guardMust(ldb.Close()); ldb = nil })
	measure("clean-reopen-NodeTree", func() { ldb, tree = guardOpen(database); openCalls++; reopenCalls++ })
	snapshots = append(snapshots, tailObserve(name, "clean-reopened", tree, ldb))
	measure("final-clean-close", func() { guardMust(ldb.Close()); ldb = nil })
	closedFiles := treeClosedFiles(database)
	var usage syscall.Rusage
	guardMust(syscall.Getrusage(syscall.RUSAGE_SELF, &usage))
	peak := usage.Maxrss
	if runtime.GOOS == "linux" {
		peak *= 1024
	}
	aliasAfter := []any{}
	for i, alias := range aliases {
		summary := targetSummary(alias)
		require(bytes.Equal(resourceJSON(summary), resourceJSON(aliasBefore[i])), "retained original map alias changed")
		aliasAfter = append(aliasAfter, summary)
	}
	conformance := map[string]any{"name": name, "steps": rows, "snapshots": snapshots, "original_aliases_before": aliasBefore, "original_aliases_after": aliasAfter, "database_open_calls": openCalls, "tree_update_calls": updateCalls, "tree_bulk_commit_calls": bulkCalls, "tree_tail_commit_calls": commitCalls, "tree_prune_calls": pruneCalls, "clean_reopen_calls": reopenCalls, "consumer_result": "REFUSED"}
	measurement := map[string]any{"case": name, "mode": mode, "repetition": repetition, "phase_resources": metrics, "closed_database_files": closedFiles, "process_peak_rss_bytes": peak, "process_peak_rss_method": treePeakMethod, "conformance_sha256": resourceHash(resourceJSON(conformance)), "platform": runtime.GOOS + "/" + runtime.GOARCH, "go_version": runtime.Version()}
	runtime.KeepAlive(aliases)
	runtime.KeepAlive(target)
	runtime.KeepAlive(files)
	fmt.Println("PATCH_TREE_TAIL=" + string(resourceJSON(map[string]any{"conformance": conformance, "measurement": measurement})))
}
