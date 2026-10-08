//go:build candidate_bulk_tail && (darwin || linux)

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
)

type bulkInput struct {
	Name     string `json:"name"`
	Keys     int    `json:"keys"`
	Versions int    `json:"versions"`
	Retain   int    `json:"retain"`
	Churn    int    `json:"churn"`
	Policy   string `json:"policy"`
}

func bulkInputs() []bulkInput {
	out := []bulkInput{}
	for _, w := range [][3]int{{64, 16, 8}, {256, 32, 32}, {1024, 64, 128}} {
		for _, policy := range []string{"replay-pruned", "bulk-tail"} {
			out = append(out, bulkInput{fmt.Sprintf("%s-%d-%d-%d", policy, w[0], w[1], w[2]), w[0], w[1], 4, w[2], policy})
		}
	}
	return out
}
func bulkMust(err error) {
	if err != nil {
		panic(err)
	}
}
func bulkIdentifier(item bulkInput, height int) types.HashHeight {
	if height == 0 {
		return types.ZeroHashHeight
	}
	return types.HashHeight{Height: uint64(height), Hash: types.NewHash([]byte(fmt.Sprintf("synthetic-bulk-tail-v1/%d/%d/%d/A/%d", item.Keys, item.Versions, item.Churn, height)))}
}
func bulkIDRecord(value types.HashHeight) any {
	return map[string]any{"height": value.Height, "hash": value.Hash.String()}
}
func bulkKey(index int) []byte {
	address := bytes.Repeat([]byte{0x11}, 20)
	binary.BigEndian.PutUint32(address[16:], uint32(index))
	return append(append(append([]byte{3}, address...), 3), bytes.Repeat([]byte{0x22}, 10)...)
}
func bulkPatch(item bulkInput, height int) db.Patch {
	p := db.NewPatch()
	count := item.Churn
	start := (height - 2) * item.Churn % item.Keys
	if height == 1 {
		count = item.Keys
		start = 0
	}
	for offset := 0; offset < count; offset++ {
		index := (start + offset) % item.Keys
		if height > 1 && height%3 == 0 && offset%3 == 0 {
			p.Delete(bulkKey(index))
			continue
		}
		value := make([]byte, 32)
		amount := uint64(height*item.Keys + index + 1)
		if height > 1 && height%4 == 0 && offset == 1 {
			amount = 0
		}
		binary.BigEndian.PutUint64(value[24:], amount)
		p.Put(bulkKey(index), value)
	}
	return p
}
func bulkStorage(ldb *leveldb.DB) any {
	counts := map[string]int{"frontier": 0, "node": 0, "refcount": 0, "version": 0, "format": 0}
	families := map[byte]string{0: "frontier", 1: "node", 2: "refcount", 3: "version", 5: "format"}
	digest := sha256.New()
	records, keyBytes, valueBytes := 0, 0, 0
	heights := []uint64{}
	width := make([]byte, 8)
	iter := ldb.NewIterator(nil, nil)
	for iter.Next() {
		k, v := iter.Key(), iter.Value()
		if len(k) == 0 {
			panic("empty logical store key")
		}
		family, ok := families[k[0]]
		if !ok {
			panic("unknown store family")
		}
		counts[family]++
		records++
		keyBytes += len(k)
		valueBytes += len(v)
		binary.BigEndian.PutUint64(width, uint64(len(k)))
		digest.Write(width)
		digest.Write(k)
		binary.BigEndian.PutUint64(width, uint64(len(v)))
		digest.Write(width)
		digest.Write(v)
		if family == "version" {
			if len(k) != 9 {
				panic("wrong version key")
			}
			heights = append(heights, binary.BigEndian.Uint64(k[1:]))
		}
	}
	iter.Release()
	bulkMust(iter.Error())
	return map[string]any{"records": records, "key_bytes": keyBytes, "value_bytes": valueBytes, "family_counts": counts, "retained_heights": heights, "records_sha256": hex.EncodeToString(digest.Sum(nil))}
}
func bulkNullableBytes(value []byte) any {
	if value == nil {
		return nil
	}
	return hex.EncodeToString(value)
}
func bulkNullableError(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}
func bulkObserve(tree *trie.NodeTree, ldb *leveldb.DB, item bulkInput, round int) (any, map[string]int64) {
	rows := []any{}
	rootNs, proofNs := int64(0), int64(0)
	for _, height := range []int{0, item.Versions - 4, item.Versions - 3, item.Versions - 2, item.Versions - 1, item.Versions, item.Versions + 1} {
		for _, index := range []int{-1, 0, item.Keys - 1, item.Keys, ((item.Versions-2)*item.Churn%item.Keys + 1) % item.Keys, (item.Versions/3*3 - 2) * item.Churn % item.Keys} {
			row := map[string]any{"identifier": bulkIDRecord(bulkIdentifier(item, height)), "key": nil, "root": nil, "value": nil, "proof": nil, "error": nil}
			if index == -1 {
				start := time.Now()
				root, err := tree.Root(bulkIdentifier(item, height))
				rootNs += time.Since(start).Nanoseconds()
				row["root"] = root.String()
				row["error"] = bulkNullableError(err)
			} else {
				raw := bulkKey(index)
				start := time.Now()
				value, proof, err := tree.Prove(bulkIdentifier(item, height), raw)
				proofNs += time.Since(start).Nanoseconds()
				row["key"] = hex.EncodeToString(raw)
				row["value"] = bulkNullableBytes(value)
				row["proof"] = bulkNullableBytes(proof)
				row["error"] = bulkNullableError(err)
			}
			rows = append(rows, row)
		}
	}
	return map[string]any{"round": round, "frontier": bulkIDRecord(tree.FrontierIdentifier()), "storage": bulkStorage(ldb), "reads": rows}, map[string]int64{"root_calls": 7, "root_elapsed_ns": rootNs, "proof_calls": 35, "proof_elapsed_ns": proofNs}
}
func bulkPhysicalClosed(dir string) any {
	files, total, largest := int64(0), int64(0), int64(0)
	entries, err := os.ReadDir(dir)
	bulkMust(err)
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(dir, entry.Name()))
		bulkMust(err)
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			panic("non-regular owned database entry")
		}
		files++
		total += info.Size()
		if info.Size() > largest {
			largest = info.Size()
		}
	}
	return map[string]int64{"regular_files": files, "file_bytes": total, "largest_file_bytes": largest}
}
func bulkOpen(dir string) (*leveldb.DB, *trie.NodeTree) {
	ldb, err := leveldb.OpenFile(dir, nil)
	bulkMust(err)
	tree, err := trie.NewNodeTree(ldb)
	if err != nil {
		ldb.Close()
		panic(err)
	}
	return ldb, tree
}

type bulkPlan struct {
	height     int
	patch      db.Patch
	operations int
}

func bulkPrepare(item bulkInput) ([]bulkPlan, any) {
	plans := []bulkPlan{}
	var seed any
	first := 1
	if item.Policy == "bulk-tail" {
		first = item.Versions - item.Retain + 1
		values := map[int][]byte{}
		for h := 1; h <= first; h++ {
			count, start := item.Churn, (h-2)*item.Churn%item.Keys
			if h == 1 {
				count, start = item.Keys, 0
			}
			for offset := 0; offset < count; offset++ {
				index := (start + offset) % item.Keys
				if h > 1 && h%3 == 0 && offset%3 == 0 {
					delete(values, index)
					continue
				}
				value := make([]byte, 32)
				amount := uint64(h*item.Keys + index + 1)
				if h > 1 && h%4 == 0 && offset == 1 {
					amount = 0
				}
				binary.BigEndian.PutUint64(value[24:], amount)
				values[index] = value
			}
		}
		patch := db.NewPatch()
		digest := sha256.New()
		width := make([]byte, 8)
		for index := 0; index < item.Keys; index++ {
			value, present := values[index]
			if !present {
				continue
			}
			raw := bulkKey(index)
			patch.Put(raw, value)
			binary.BigEndian.PutUint64(width, uint64(len(raw)))
			digest.Write(width)
			digest.Write(raw)
			binary.BigEndian.PutUint64(width, uint64(len(value)))
			digest.Write(width)
			digest.Write(value)
		}
		seed = map[string]any{"height": first, "present_keys": len(values), "raw_map_sha256": hex.EncodeToString(digest.Sum(nil))}
		plans = append(plans, bulkPlan{first, patch, len(values)})
		first++
	}
	for h := first; h <= item.Versions; h++ {
		count := item.Churn
		if h == 1 {
			count = item.Keys
		}
		plans = append(plans, bulkPlan{h, bulkPatch(item, h), count})
	}
	return plans, seed
}
func bulkChild(item bulkInput, dir string) any {
	info, err := os.Lstat(dir)
	bulkMust(err)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || filepath.Base(dir) != item.Name {
		panic("unowned resource directory")
	}
	marker, err := os.ReadFile(filepath.Join(dir, ".owned"))
	bulkMust(err)
	if string(marker) != nodeTree+"\n"+item.Name+"\n" {
		panic("wrong resource ownership marker")
	}
	entries, err := os.ReadDir(dir)
	bulkMust(err)
	if len(entries) != 1 || entries[0].Name() != ".owned" || entries[0].Type()&os.ModeSymlink != 0 {
		panic("resource child requires a fresh owned directory")
	}
	prepareStart := time.Now()
	plans, seed := bulkPrepare(item)
	prepareNs := time.Since(prepareStart).Nanoseconds()
	database := filepath.Join(dir, "database")
	start := time.Now()
	ldb, tree := bulkOpen(database)
	openNs := time.Since(start).Nanoseconds()
	closed := false
	defer func() {
		if !closed {
			ldb.Close()
		}
	}()
	updateNs, commitNs, pruneNs, prunes := int64(0), int64(0), int64(0), 0
	buildStart := time.Now()
	operations := 0
	var seedCommitError any
	bulkCommits := 0
	for _, plan := range plans {
		h, p := plan.height, plan.patch
		operations += plan.operations
		start = time.Now()
		bulkMust(tree.Update(p))
		updateNs += time.Since(start).Nanoseconds()
		start = time.Now()
		if item.Policy == "bulk-tail" && h == item.Versions-item.Retain+1 {
			err := tree.Commit(bulkIdentifier(item, h))
			if err == nil || err.Error() != "trie: commit height must be exactly one above the frontier" {
				panic("regular seed commit did not refuse the selected height gap")
			}
			seedCommitError = err.Error()
			bulkMust(tree.CommitBulk(bulkIdentifier(item, h)))
			bulkCommits++
		} else {
			bulkMust(tree.Commit(bulkIdentifier(item, h)))
		}
		commitNs += time.Since(start).Nanoseconds()
		if item.Policy == "replay-pruned" && h > item.Retain {
			start = time.Now()
			bulkMust(tree.Prune(uint64(h - item.Retain + 1)))
			pruneNs += time.Since(start).Nanoseconds()
			prunes++
		}
	}
	buildNs := time.Since(buildStart).Nanoseconds()
	first, firstTimes := bulkObserve(tree, ldb, item, 0)
	start = time.Now()
	bulkMust(ldb.Close())
	closeNs := time.Since(start).Nanoseconds()
	closed = true
	initialFiles := bulkPhysicalClosed(database)
	start = time.Now()
	ldb, tree = bulkOpen(database)
	reopenNs := time.Since(start).Nanoseconds()
	closed = false
	second, secondTimes := bulkObserve(tree, ldb, item, 1)
	start = time.Now()
	bulkMust(ldb.CompactRange(util.Range{}))
	compactNs := time.Since(start).Nanoseconds()
	bulkMust(ldb.Close())
	closed = true
	compactedFiles := bulkPhysicalClosed(database)
	start = time.Now()
	ldb, tree = bulkOpen(database)
	compactReopenNs := time.Since(start).Nanoseconds()
	closed = false
	third, thirdTimes := bulkObserve(tree, ldb, item, 2)
	bulkMust(ldb.Close())
	closed = true
	finalFiles := bulkPhysicalClosed(database)
	var usage syscall.Rusage
	bulkMust(syscall.Getrusage(syscall.RUSAGE_SELF, &usage))
	peak := usage.Maxrss
	if runtime.GOOS != "darwin" {
		peak *= 1024
	}
	return map[string]any{"conformance": map[string]any{"input": item, "patch_calls": len(plans), "input_operations": operations, "commit_calls": len(plans) - bulkCommits, "bulk_commit_calls": bulkCommits, "regular_seed_commit_error": seedCommitError, "bulk_seed_manifest": seed, "prune_calls": prunes, "manual_compaction_calls": 1, "rounds": []any{first, second, third}},
		"measurements": map[string]any{"case": item.Name, "platform": runtime.GOOS + "/" + runtime.GOARCH, "peak_rss_bytes": peak, "peak_rss_method": "getrusage(RUSAGE_SELF), child-process high-water mark; includes fixture, NodeTree and LevelDB",
			"initial_open_elapsed_ns": openNs, "prepared_patch_update_commit_prune_elapsed_ns": buildNs, "fixture_input_preparation_elapsed_ns": prepareNs, "update_elapsed_ns": updateNs, "commit_elapsed_ns": commitNs, "prune_elapsed_ns": pruneNs, "initial_close_elapsed_ns": closeNs, "reopen_elapsed_ns": reopenNs, "manual_compaction_elapsed_ns": compactNs, "compacted_reopen_elapsed_ns": compactReopenNs,
			"query_timings": []any{firstTimes, secondTimes, thirdTimes}, "closed_before_compaction": initialFiles, "closed_after_compaction": compactedFiles, "closed_after_final_reopen": finalFiles}}
}
func generateBulkResources() any {
	exe, err := os.Executable()
	bulkMust(err)
	cases := []any{}
	measurements := []any{}
	for _, item := range bulkInputs() {
		temporary, err := os.MkdirTemp("", "candidate-bulk-resources-")
		bulkMust(err)
		func() {
			defer func() {
				bulkMust(os.RemoveAll(temporary))
				if _, err := os.Lstat(temporary); !os.IsNotExist(err) {
					panic("owned resource directory not removed")
				}
			}()
			dir := filepath.Join(temporary, item.Name)
			bulkMust(os.Mkdir(dir, 0o700))
			bulkMust(os.WriteFile(filepath.Join(dir, ".owned"), []byte(nodeTree+"\n"+item.Name+"\n"), 0o600))
			command := exec.Command(exe, "--verified-node-tree", nodeTree, "--bulk-child", item.Name, dir)
			var out, diagnostics bytes.Buffer
			command.Stdout = &out
			command.Stderr = &diagnostics
			if err := command.Run(); err != nil {
				panic(fmt.Sprintf("owned bulk child %s failed: %v; diagnostics: %s", item.Name, err, diagnostics.String()))
			}
			if diagnostics.Len() != 0 {
				panic("unexpected child diagnostics")
			}
			var row map[string]any
			bulkMust(json.Unmarshal(out.Bytes(), &row))
			if len(row) != 2 {
				panic("unexpected child record")
			}
			cases = append(cases, row["conformance"])
			measurements = append(measurements, row["measurements"])
		}()
	}
	return map[string]any{"format_version": 1, "kind": "candidate-bulk-tail-research", "backend": "NodeTree",
		"source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"scope":  map[string]bool{"actual_NodeTree_CommitBulk_executed": true, "fixture_seed_not_authenticated_snapshot": true, "node_snapshot_import_executed": false, "historical_archive_replay_qualified": false, "synthetic": true, "unsigned": true, "actual_NodeTree_disk_APIs_executed": true, "small_owned_temporary_disk_LevelDB": true, "normal_child_measurement_processes": true, "controlled_clean_reopen_executed": true, "manual_compaction_executed": true, "logical_storage_records_measured": true, "owned_databases_removed": true, "variable_resource_samples_separate_from_conformance": true, "chain_component_Init_executed": false, "chain_Start_executed": false, "background_build_executed": false, "full_node_started": false, "node_tests_executed": false, "network_execution": false, "RPC_executed": false, "signing": false, "transactions": false, "power_loss_qualified": false, "torn_write_qualified": false, "production_crash_recovery_qualified": false, "authenticated_retained_version_provenance_qualified": false, "realistic_retention_resource_budgets_qualified": false, "header_authentication_executed": false, "profile_agreed": false, "network_activation_authenticated": false, "runtime_state_proof_acceptance": false}, "cases": cases, "measurements": measurements}
}
func init() {
	bulkResourceGenerator = generateBulkResources
	if len(os.Args) > 3 && os.Args[3] == "--bulk-child" {
		require(len(os.Args) == 6 && os.Args[1] == "--verified-node-tree" && os.Args[2] == nodeTree, "unselected bulk child arguments")
		info, ok := debug.ReadBuildInfo()
		require(ok, "missing bulk child build provenance")
		selected := false
		for _, dependency := range info.Deps {
			if dependency.Path == "github.com/zenon-network/go-zenon" {
				selected = dependency.Version == "v0.0.0" && dependency.Replace != nil && dependency.Replace.Path == "../reference-node" && (dependency.Replace.Version == "" || dependency.Replace.Version == "(devel)")
			}
		}
		require(selected, "expected separately verified local candidate bulk source")
		for _, item := range bulkInputs() {
			if item.Name == os.Args[4] {
				bulkMust(json.NewEncoder(os.Stdout).Encode(bulkChild(item, os.Args[5])))
				os.Exit(0)
			}
		}
		panic("unselected bulk child fixture")
	}
}
