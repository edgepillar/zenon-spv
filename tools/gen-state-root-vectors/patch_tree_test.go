//go:build candidate_patch_tree && (darwin || linux)

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
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

const treePeakMethod = "getrusage(RUSAGE_SELF) after final phase and closed-file inventory, before final result binding/serialization; lifetime high water includes startup, fixture/selection/pre-operation GC, interim conformance queries and inventory"

func treeFamilies() []string {
	return []string{"empty-complete", "complete-stored-zero", "complete-256", "delete-reinsert",
		"file-selection-refusal", "transient-cap-refusal", "unsupported-key-refusal",
		"empty-value-refusal", "wrong-selected-root-refusal", "omitted-zero-refusal", "omitted-delete-refusal"}
}

func treeComplete(count int) map[int][]byte {
	state := map[int][]byte{}
	for i := 0; i < count; i++ {
		amount := uint64(i + 1)
		if i == 0 {
			amount = 0
		}
		state[i] = guardValue(amount)
	}
	return state
}

// The intended complete map is selected from independent fixture rules before
// file import or storage reads. It is synthetic, unsigned and never a header.
func treeSelected(name string) map[int][]byte {
	count := 8
	if name == "empty-complete" {
		count = 0
	} else if name == "complete-256" {
		count = 256
	}
	state := treeComplete(count)
	if name == "delete-reinsert" {
		delete(state, 2)
		state[1], state[6], state[8] = guardValue(0), guardValue(0), guardValue(10)
	}
	if name == "omitted-delete-refusal" {
		delete(state, 2)
		state[1] = guardValue(0)
	}
	return state
}

func treeInput(name string) patchResourceInput {
	target, raw, count := map[string]string{}, []byte{}, uint64(0)
	caps := importTargetCeilings
	put := func(key, value []byte) {
		raw = append(raw, 1)
		raw = binary.AppendUvarint(raw, uint64(len(key)))
		raw = append(raw, key...)
		raw = binary.AppendUvarint(raw, uint64(len(value)))
		raw = append(raw, value...)
		count++
	}
	del := func(key []byte) {
		raw = append(raw, 0)
		raw = binary.AppendUvarint(raw, uint64(len(key)))
		raw = append(raw, key...)
		count++
	}
	switch name {
	case "delete-reinsert", "transient-cap-refusal", "unsupported-key-refusal", "empty-value-refusal", "omitted-delete-refusal":
		for index, value := range treeComplete(8) {
			target[hex.EncodeToString(guardKey(index))] = hex.EncodeToString(value)
		}
		switch name {
		case "delete-reinsert":
			del(guardKey(2))
			put(guardKey(1), guardValue(0))
			put(guardKey(8), guardValue(9))
			put(guardKey(8), guardValue(10))
			del(guardKey(6))
			put(guardKey(6), guardValue(0))
		case "transient-cap-refusal":
			caps = importTargetLimits{8, 1024}
			put(guardKey(8), guardValue(10))
			del(guardKey(2))
		case "unsupported-key-refusal":
			key := guardKey(8)
			key[21] = 5 // An excluded account key family; never a balance proof.
			put(key, guardValue(9))
		case "empty-value-refusal":
			put(guardKey(8), []byte{})
		case "omitted-delete-refusal":
			put(guardKey(1), guardValue(0))
		}
	default:
		size := 8
		if name == "empty-complete" {
			size = 0
		} else if name == "complete-256" {
			size = 256
		}
		state := treeComplete(size)
		for i := 0; i < size; i++ {
			if name != "omitted-zero-refusal" || i != 0 {
				put(guardKey(i), state[i])
			}
		}
	}
	selection := importSelection{name, uint64(len(raw)), count, types.NewHash(raw).String()}
	if name == "file-selection-refusal" {
		selection.ChangesHash = types.ZeroHash.String()
	}
	return patchResourceInput{importInput{decodeInput{name, raw}, importCeilings, selection, "none"}, target, caps}
}

// A private finite balance-only handoff preflight. It accepts no arbitrary key
// domains, empty values, authenticated snapshot claims or production profile.
// Complete map and selected root checks precede creating any database directory.
func treePreflight(target map[string]string, selected types.Hash) (types.Hash, string) {
	keys := make([]string, 0, len(target))
	for key := range target {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	paths, values := []trie.Path{}, [][]byte{}
	for _, key := range keys {
		raw, err := hex.DecodeString(key)
		if err != nil || len(raw) != 32 || raw[0] != 3 || raw[21] != 3 {
			return types.ZeroHash, "unsupported_balance_key"
		}
		value, err := hex.DecodeString(target[key])
		if err != nil || len(value) != 32 {
			return types.ZeroHash, "unsupported_balance_value"
		}
		paths, values = append(paths, trie.Path(types.NewHash(raw))), append(values, value)
	}
	root, err := trie.RootOfLeaves(paths, values)
	guardMust(err)
	if root != selected {
		return root, "selected_root_mismatch"
	}
	return root, ""
}

type treeReplayRecorder struct {
	db.PatchReplayer
	events *[]importEvent
}

func (r *treeReplayRecorder) Put(key, value []byte) {
	encoded := hex.EncodeToString(value)
	*r.events = append(*r.events, importEvent{"Put", hex.EncodeToString(key), &encoded})
	r.PatchReplayer.Put(key, value)
}
func (r *treeReplayRecorder) Delete(key []byte) {
	*r.events = append(*r.events, importEvent{"Delete", hex.EncodeToString(key), nil})
	r.PatchReplayer.Delete(key)
}

type treeRecordedPatch struct {
	db.Patch
	events *[]importEvent
}

func (p *treeRecordedPatch) Replay(target db.PatchReplayer) error {
	return p.Patch.Replay(&treeReplayRecorder{target, p.events})
}

func treeSeed(target map[string]string, events *[]importEvent) db.Patch {
	keys := make([]string, 0, len(target))
	for key := range target {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	patch := db.NewPatch()
	for _, key := range keys {
		raw, err := hex.DecodeString(key)
		guardMust(err)
		value, err := hex.DecodeString(target[key])
		guardMust(err)
		patch.Put(raw, value)
	}
	return &treeRecordedPatch{patch, events}
}

func treeObserve(name, label string, tree *trie.NodeTree, ldb *leveldb.DB) any {
	rows := []any{}
	for _, height := range []int{0, 1, 3, 4} {
		id := guardIdentifier(name, height)
		root, err := tree.Root(id)
		rows = append(rows, map[string]any{"identifier": guardIDRecord(id), "key": nil, "root": root.String(), "value": nil, "proof": nil, "error": guardNullableError(err)})
		for _, index := range []int{0, 1, 2, 6, 8, 255, 256} {
			key := guardKey(index)
			value, proof, failure := tree.Prove(id, key)
			rows = append(rows, map[string]any{"identifier": guardIDRecord(id), "key": hex.EncodeToString(key), "root": nil, "value": guardNullableBytes(value), "proof": guardNullableBytes(proof), "error": guardNullableError(failure)})
		}
	}
	return map[string]any{"label": label, "frontier": guardIDRecord(tree.FrontierIdentifier()), "storage": guardStorage(ldb), "reads": rows}
}

func treeClosedFiles(path string) any {
	files, total := uint64(0), uint64(0)
	err := filepath.WalkDir(path, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		require(info.Mode().IsRegular() && info.Size() >= 0, "unexpected closed database file")
		files++
		total += uint64(info.Size())
		return nil
	})
	guardMust(err)
	return map[string]any{"regular_files": files, "bytes": total}
}

// One selected operation sequence per fresh process. Only named phases are
// timed. Interim full storage/proof observations, fixture/selection and report
// work are outside phase timing/allocation, but contribute to lifetime RSS.
func TestPatchTreeChild(t *testing.T) {
	name, mode := os.Getenv("PATCH_TREE_CASE"), os.Getenv("PATCH_TREE_MODE")
	repetition, err := strconv.Atoi(os.Getenv("PATCH_TREE_REPETITION"))
	selected := false
	for _, family := range treeFamilies() {
		selected = selected || name == family
	}
	if !selected || err != nil || repetition < 0 || repetition >= 3 || (mode != "plain" && mode != "allocation") {
		t.Fatal("unselected patch tree child")
	}
	item := treeInput(name)
	wanted, wantedMap := guardSelectedRoot(treeSelected(name))
	if name == "wrong-selected-root-refusal" {
		wanted = types.ZeroHash
	}
	before, rawSize, rawHash := targetSummary(item.target), len(item.input.raw), resourceHash(item.input.raw)
	rootDir := t.TempDir()
	path, database := filepath.Join(rootDir, "owned.raw"), filepath.Join(rootDir, "tree")
	guardMust(os.WriteFile(path, item.input.raw, 0600))
	file, err := os.Open(path)
	guardMust(err)
	defer func() { guardMust(file.Close()) }()
	_, err = file.Seek(7, io.SeekStart)
	guardMust(err)
	item.input.raw = nil
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
	runtime.GC()
	var result importFileExecution
	measure("opened-file-to-owned-map", func() { result = importFileApply(file, item.input, item.target, item.caps) })
	refusal := ""
	var observedRoot any
	if result.refusal != "" {
		refusal = "import_" + result.refusal
	} else {
		measure("complete-balance-map-and-root-selection", func() {
			actual, reason := treePreflight(result.target, wanted)
			refusal = reason
			if reason != "unsupported_balance_key" && reason != "unsupported_balance_value" {
				observedRoot = actual.String()
			}
		})
	}
	steps, events := []any{}, []importEvent{}
	var closedFiles any
	openCalls, updateCalls, commitCalls, reopenCalls := 0, 0, 0, 0
	if refusal == "" {
		var ldb *leveldb.DB
		var tree *trie.NodeTree
		defer func() {
			if ldb != nil {
				guardMust(ldb.Close())
			}
		}()
		measure("open-fresh-NodeTree", func() { ldb, tree = guardOpen(database); openCalls++ })
		steps = append(steps, treeObserve(name, "fresh", tree, ldb))
		measure("complete-sorted-seed-patch-and-Update", func() { guardMust(tree.Update(treeSeed(result.target, &events))); updateCalls++ })
		steps = append(steps, treeObserve(name, "staged", tree, ldb))
		measure("CommitBulk", func() { guardMust(tree.CommitBulk(guardIdentifier(name, 3))); commitCalls++ })
		steps = append(steps, treeObserve(name, "seed-committed", tree, ldb))
		measure("clean-close", func() { guardMust(ldb.Close()); ldb = nil })
		measure("clean-reopen-NodeTree", func() { ldb, tree = guardOpen(database); openCalls++; reopenCalls++ })
		steps = append(steps, treeObserve(name, "clean-reopened", tree, ldb))
		measure("final-clean-close", func() { guardMust(ldb.Close()); ldb = nil })
		closedFiles = treeClosedFiles(database)
	} else if _, err := os.Lstat(database); !os.IsNotExist(err) {
		t.Fatal("refused handoff created storage")
	}
	var usage syscall.Rusage
	guardMust(syscall.Getrusage(syscall.RUSAGE_SELF, &usage))
	peak := usage.Maxrss
	if runtime.GOOS == "linux" {
		peak *= 1024
	}
	cursor, err := file.Seek(0, io.SeekCurrent)
	guardMust(err)
	after, err := os.ReadFile(path)
	guardMust(err)
	if cursor != 7 || len(after) != rawSize || resourceHash(after) != rawHash || string(resourceJSON(before)) != string(resourceJSON(targetSummary(item.target))) {
		t.Fatal("source or original map alias changed")
	}
	importVerdict, verdict := "STAGED", "COMMITTED_RESEARCH"
	if result.refusal != "" {
		importVerdict = "REJECTED"
	}
	if refusal != "" {
		verdict = "REJECTED"
	}
	imported := map[string]any{"name": name, "source_fault": "none", "import_fault": "none", "limits": item.input.limits, "selection": item.input.selection, "target_limits": item.caps,
		"file_before_bytes": rawSize, "file_before_sha256": rawHash, "file_after_bytes": len(after), "file_after_sha256": resourceHash(after),
		"file_stat_calls": result.statCalls, "file_read_calls": result.readCalls, "file_buffer_bytes": result.bufferBytes, "file_read_bytes": result.readBytes,
		"source_cursor_available": true, "source_cursor_preserved": true, "preflight_records": len(result.stage.expected), "raw_copies": result.rawCopies,
		"constructor_calls": result.constructorCalls, "default_replay_calls": result.replayCalls, "target_clone_calls": result.cloneCalls, "target_cloned_entries": result.clonedEntries,
		"staging_callbacks": resourceCallbacks(result.stage.events), "staging_target": targetSummary(result.stage.state), "target_before": before, "target_after": targetSummary(result.target),
		"original_alias_after": targetSummary(item.target), "target_replacements": result.replacements, "research_import_result": importVerdict, "refusal": result.refusal, "consumer_result": "REFUSED"}
	conformance := map[string]any{"name": name, "import": imported, "selected_complete_map": wantedMap, "selected_root": wanted.String(), "preflight_root": observedRoot,
		"handoff_refusal": refusal, "database_open_calls": openCalls, "tree_update_calls": updateCalls, "tree_bulk_commit_calls": commitCalls, "clean_reopen_calls": reopenCalls,
		"tree_staging_callbacks": resourceCallbacks(events), "snapshots": steps, "research_handoff_result": verdict, "consumer_result": "REFUSED"}
	measurement := map[string]any{"case": name, "mode": mode, "repetition": repetition, "phase_resources": metrics, "closed_database_files": closedFiles,
		"process_peak_rss_bytes": peak, "process_peak_rss_method": treePeakMethod, "conformance_sha256": resourceHash(resourceJSON(conformance)), "platform": runtime.GOOS + "/" + runtime.GOARCH, "go_version": runtime.Version()}
	runtime.KeepAlive(item)
	runtime.KeepAlive(result)
	runtime.KeepAlive(file)
	runtime.KeepAlive(before)
	fmt.Println("PATCH_TREE=" + string(resourceJSON(map[string]any{"conformance": conformance, "measurement": measurement})))
}
