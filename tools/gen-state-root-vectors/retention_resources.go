//go:build candidate_retention && (darwin || linux)

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

type retentionInput struct {
	Name     string `json:"name"`
	Keys     int    `json:"keys"`
	Versions int    `json:"versions"`
	Retain   int    `json:"retain"`
}

func retentionInputs() []retentionInput {
	return []retentionInput{{"archive-64-16", 64, 16, 16}, {"pruned-64-16", 64, 16, 4}, {"archive-256-32", 256, 32, 32}, {"pruned-256-32", 256, 32, 4}}
}
func retentionMust(err error) {
	if err != nil {
		panic(err)
	}
}
func retentionIdentifier(keys, height int) types.HashHeight {
	if height == 0 {
		return types.ZeroHashHeight
	}
	return types.HashHeight{Height: uint64(height), Hash: types.NewHash([]byte(fmt.Sprintf("synthetic-retention-resource-v1/%d/A/%d", keys, height)))}
}
func retentionIDRecord(value types.HashHeight) any {
	return map[string]any{"height": value.Height, "hash": value.Hash.String()}
}
func retentionKey(index int) []byte {
	address := bytes.Repeat([]byte{0x11}, 20)
	binary.BigEndian.PutUint32(address[16:], uint32(index))
	return append(append(append([]byte{3}, address...), 3), bytes.Repeat([]byte{0x22}, 10)...)
}
func retentionPatch(item retentionInput, height int) db.Patch {
	p := db.NewPatch()
	count := 8
	start := (height - 2) * 8 % item.Keys
	if height == 1 {
		count = item.Keys
		start = 0
	}
	for offset := 0; offset < count; offset++ {
		index := (start + offset) % item.Keys
		if height > 1 && height%3 == 0 && offset%3 == 0 {
			p.Delete(retentionKey(index))
			continue
		}
		value := make([]byte, 32)
		amount := uint64(height*item.Keys + index + 1)
		if height > 1 && height%4 == 0 && offset == 1 {
			amount = 0
		}
		binary.BigEndian.PutUint64(value[24:], amount)
		p.Put(retentionKey(index), value)
	}
	return p
}
func retentionStorage(ldb *leveldb.DB) any {
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
	retentionMust(iter.Error())
	return map[string]any{"records": records, "key_bytes": keyBytes, "value_bytes": valueBytes, "family_counts": counts, "retained_heights": heights, "records_sha256": hex.EncodeToString(digest.Sum(nil))}
}
func retentionNullableBytes(value []byte) any {
	if value == nil {
		return nil
	}
	return hex.EncodeToString(value)
}
func retentionNullableError(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}
func retentionObserve(tree *trie.NodeTree, ldb *leveldb.DB, item retentionInput, round int) (any, map[string]int64) {
	rows := []any{}
	rootNs, proofNs := int64(0), int64(0)
	for _, height := range []int{0, 1, item.Versions / 4, item.Versions / 2, item.Versions - 3, item.Versions, item.Versions + 1} {
		for _, index := range []int{-1, 0, item.Keys - 1, item.Keys, ((item.Versions-2)*8%item.Keys + 1) % item.Keys, (item.Versions/3*3 - 2) * 8 % item.Keys} {
			row := map[string]any{"identifier": retentionIDRecord(retentionIdentifier(item.Keys, height)), "key": nil, "root": nil, "value": nil, "proof": nil, "error": nil}
			if index == -1 {
				start := time.Now()
				root, err := tree.Root(retentionIdentifier(item.Keys, height))
				rootNs += time.Since(start).Nanoseconds()
				row["root"] = root.String()
				row["error"] = retentionNullableError(err)
			} else {
				raw := retentionKey(index)
				start := time.Now()
				value, proof, err := tree.Prove(retentionIdentifier(item.Keys, height), raw)
				proofNs += time.Since(start).Nanoseconds()
				row["key"] = hex.EncodeToString(raw)
				row["value"] = retentionNullableBytes(value)
				row["proof"] = retentionNullableBytes(proof)
				row["error"] = retentionNullableError(err)
			}
			rows = append(rows, row)
		}
	}
	return map[string]any{"round": round, "frontier": retentionIDRecord(tree.FrontierIdentifier()), "storage": retentionStorage(ldb), "reads": rows}, map[string]int64{"root_calls": 7, "root_elapsed_ns": rootNs, "proof_calls": 35, "proof_elapsed_ns": proofNs}
}
func retentionPhysicalClosed(dir string) any {
	files, total, largest := int64(0), int64(0), int64(0)
	entries, err := os.ReadDir(dir)
	retentionMust(err)
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(dir, entry.Name()))
		retentionMust(err)
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
func retentionOpen(dir string) (*leveldb.DB, *trie.NodeTree) {
	ldb, err := leveldb.OpenFile(dir, nil)
	retentionMust(err)
	tree, err := trie.NewNodeTree(ldb)
	if err != nil {
		ldb.Close()
		panic(err)
	}
	return ldb, tree
}
func retentionChild(item retentionInput, dir string) any {
	info, err := os.Lstat(dir)
	retentionMust(err)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || filepath.Base(dir) != item.Name {
		panic("unowned resource directory")
	}
	marker, err := os.ReadFile(filepath.Join(dir, ".owned"))
	retentionMust(err)
	if string(marker) != nodeTree+"\n"+item.Name+"\n" {
		panic("wrong resource ownership marker")
	}
	entries, err := os.ReadDir(dir)
	retentionMust(err)
	if len(entries) != 1 || entries[0].Name() != ".owned" || entries[0].Type()&os.ModeSymlink != 0 {
		panic("resource child requires a fresh owned directory")
	}
	database := filepath.Join(dir, "database")
	start := time.Now()
	ldb, tree := retentionOpen(database)
	openNs := time.Since(start).Nanoseconds()
	closed := false
	defer func() {
		if !closed {
			ldb.Close()
		}
	}()
	updateNs, commitNs, pruneNs, prunes := int64(0), int64(0), int64(0), 0
	buildStart := time.Now()
	for h := 1; h <= item.Versions; h++ {
		p := retentionPatch(item, h)
		start = time.Now()
		retentionMust(tree.Update(p))
		updateNs += time.Since(start).Nanoseconds()
		start = time.Now()
		retentionMust(tree.Commit(retentionIdentifier(item.Keys, h)))
		commitNs += time.Since(start).Nanoseconds()
		if h > item.Retain {
			start = time.Now()
			retentionMust(tree.Prune(uint64(h - item.Retain + 1)))
			pruneNs += time.Since(start).Nanoseconds()
			prunes++
		}
	}
	buildNs := time.Since(buildStart).Nanoseconds()
	first, firstTimes := retentionObserve(tree, ldb, item, 0)
	start = time.Now()
	retentionMust(ldb.Close())
	closeNs := time.Since(start).Nanoseconds()
	closed = true
	initialFiles := retentionPhysicalClosed(database)
	start = time.Now()
	ldb, tree = retentionOpen(database)
	reopenNs := time.Since(start).Nanoseconds()
	closed = false
	second, secondTimes := retentionObserve(tree, ldb, item, 1)
	start = time.Now()
	retentionMust(ldb.CompactRange(util.Range{}))
	compactNs := time.Since(start).Nanoseconds()
	retentionMust(ldb.Close())
	closed = true
	compactedFiles := retentionPhysicalClosed(database)
	start = time.Now()
	ldb, tree = retentionOpen(database)
	compactReopenNs := time.Since(start).Nanoseconds()
	closed = false
	third, thirdTimes := retentionObserve(tree, ldb, item, 2)
	retentionMust(ldb.Close())
	closed = true
	finalFiles := retentionPhysicalClosed(database)
	var usage syscall.Rusage
	retentionMust(syscall.Getrusage(syscall.RUSAGE_SELF, &usage))
	peak := usage.Maxrss
	if runtime.GOOS != "darwin" {
		peak *= 1024
	}
	return map[string]any{"conformance": map[string]any{"input": item, "patch_calls": item.Versions, "input_operations": item.Keys + (item.Versions-1)*8, "commit_calls": item.Versions, "prune_calls": prunes, "manual_compaction_calls": 1, "rounds": []any{first, second, third}},
		"measurements": map[string]any{"case": item.Name, "platform": runtime.GOOS + "/" + runtime.GOARCH, "peak_rss_bytes": peak, "peak_rss_method": "getrusage(RUSAGE_SELF), child-process high-water mark; includes fixture, NodeTree and LevelDB",
			"initial_open_elapsed_ns": openNs, "patch_build_update_commit_prune_elapsed_ns": buildNs, "update_elapsed_ns": updateNs, "commit_elapsed_ns": commitNs, "prune_elapsed_ns": pruneNs, "initial_close_elapsed_ns": closeNs, "reopen_elapsed_ns": reopenNs, "manual_compaction_elapsed_ns": compactNs, "compacted_reopen_elapsed_ns": compactReopenNs,
			"query_timings": []any{firstTimes, secondTimes, thirdTimes}, "closed_before_compaction": initialFiles, "closed_after_compaction": compactedFiles, "closed_after_final_reopen": finalFiles}}
}
func generateRetentionResources() any {
	exe, err := os.Executable()
	retentionMust(err)
	cases := []any{}
	measurements := []any{}
	for _, item := range retentionInputs() {
		temporary, err := os.MkdirTemp("", "candidate-retention-resources-")
		retentionMust(err)
		func() {
			defer func() {
				retentionMust(os.RemoveAll(temporary))
				if _, err := os.Lstat(temporary); !os.IsNotExist(err) {
					panic("owned resource directory not removed")
				}
			}()
			dir := filepath.Join(temporary, item.Name)
			retentionMust(os.Mkdir(dir, 0o700))
			retentionMust(os.WriteFile(filepath.Join(dir, ".owned"), []byte(nodeTree+"\n"+item.Name+"\n"), 0o600))
			command := exec.Command(exe, "--verified-node-tree", nodeTree, "--retention-child", item.Name, dir)
			var out, diagnostics bytes.Buffer
			command.Stdout = &out
			command.Stderr = &diagnostics
			retentionMust(command.Run())
			if diagnostics.Len() != 0 {
				panic("unexpected child diagnostics")
			}
			var row map[string]any
			retentionMust(json.Unmarshal(out.Bytes(), &row))
			if len(row) != 2 {
				panic("unexpected child record")
			}
			cases = append(cases, row["conformance"])
			measurements = append(measurements, row["measurements"])
		}()
	}
	return map[string]any{"format_version": 1, "kind": "candidate-retention-resource-research", "backend": "NodeTree",
		"source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"scope":  map[string]bool{"synthetic": true, "unsigned": true, "actual_NodeTree_disk_APIs_executed": true, "small_owned_temporary_disk_LevelDB": true, "normal_child_measurement_processes": true, "controlled_clean_reopen_executed": true, "manual_compaction_executed": true, "logical_storage_records_measured": true, "owned_databases_removed": true, "variable_resource_samples_separate_from_conformance": true, "chain_component_Init_executed": false, "chain_Start_executed": false, "background_build_executed": false, "full_node_started": false, "node_tests_executed": false, "network_execution": false, "RPC_executed": false, "signing": false, "transactions": false, "power_loss_qualified": false, "torn_write_qualified": false, "production_crash_recovery_qualified": false, "authenticated_retained_version_provenance_qualified": false, "realistic_retention_resource_budgets_qualified": false, "header_authentication_executed": false, "profile_agreed": false, "network_activation_authenticated": false, "runtime_state_proof_acceptance": false}, "cases": cases, "measurements": measurements}
}
func init() {
	retentionResourceGenerator = generateRetentionResources
	if len(os.Args) > 3 && os.Args[3] == "--retention-child" {
		require(len(os.Args) == 6 && os.Args[1] == "--verified-node-tree" && os.Args[2] == nodeTree, "unselected retention child arguments")
		info, ok := debug.ReadBuildInfo()
		require(ok, "missing retention child build provenance")
		selected := false
		for _, dependency := range info.Deps {
			if dependency.Path == "github.com/zenon-network/go-zenon" {
				selected = dependency.Version == "v0.0.0" && dependency.Replace != nil && dependency.Replace.Path == "../reference-node" && (dependency.Replace.Version == "" || dependency.Replace.Version == "(devel)")
			}
		}
		require(selected, "expected separately verified local candidate retention source")
		for _, item := range retentionInputs() {
			if item.Name == os.Args[4] {
				retentionMust(json.NewEncoder(os.Stdout).Encode(retentionChild(item, os.Args[5])))
				os.Exit(0)
			}
		}
		panic("unselected retention child fixture")
	}
}
