//go:build candidate_disk_lifecycle

// SPDX-License-Identifier: GPL-3.0-only
// A finite owned disk/process-exit probe. No node service or ledger runs.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
)

const diskControlledExit = 73

type diskInput struct {
	Name       string `json:"name"`
	SeedHeight uint64 `json:"seed_height"`
	Boundary   string `json:"boundary"`
}

func diskInputs() []diskInput {
	return []diskInput{
		{"exit-after-open", 2, "after-open"},
		{"exit-after-stage", 2, "after-stage"},
		{"exit-after-commit", 2, "after-commit"},
		{"exit-after-truncate", 3, "after-truncate"},
		{"exit-after-prune", 3, "after-prune"},
		{"clean-close", 2, "after-commit"},
	}
}
func diskMust(err error) {
	if err != nil {
		panic(err)
	}
}
func diskIdentifier(fork string, height uint64) types.HashHeight {
	if height == 0 {
		return types.ZeroHashHeight
	}
	return types.HashHeight{Height: height, Hash: types.NewHash([]byte(fmt.Sprintf("synthetic-disk-lifecycle-v1/%s/%d", fork, height)))}
}
func diskIDRecord(id types.HashHeight) any {
	return map[string]any{"height": id.Height, "hash": id.Hash.String()}
}
func diskKey(missing bool) []byte {
	a := bytes.Repeat([]byte{0x11}, 20)
	token := byte(0x22)
	if missing {
		token = 0x44
	}
	return append(append(append([]byte{3}, a...), 3), bytes.Repeat([]byte{token}, 10)...)
}
func diskPatch(height uint64) db.Patch {
	value := make([]byte, 32)
	value[31] = byte(height)
	p := db.NewPatch()
	p.Put(diskKey(false), value)
	return p
}
func diskNullableHex(value []byte) any {
	if value == nil {
		return nil
	}
	return hex.EncodeToString(value)
}
func diskNullableError(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}
func diskMarker(item diskInput) []byte { return []byte(nodeTree + "\n" + item.Name + "\n") }
func diskOpenTree(dir string) (*leveldb.DB, *trie.NodeTree) {
	ldb, err := leveldb.OpenFile(filepath.Join(dir, "database"), nil)
	diskMust(err)
	tree, err := trie.NewNodeTree(ldb)
	if err != nil {
		ldb.Close()
		panic(err)
	}
	return ldb, tree
}
func diskSeed(dir string, item diskInput) {
	ldb, tree := diskOpenTree(dir)
	closed := false
	defer func() {
		if !closed {
			ldb.Close()
		}
	}()
	for h := uint64(1); h <= item.SeedHeight; h++ {
		diskMust(tree.Update(diskPatch(h)))
		diskMust(tree.Commit(diskIdentifier("A", h)))
	}
	diskMust(ldb.Close())
	closed = true
}
func diskChild(item diskInput, dir string) {
	info, err := os.Lstat(dir)
	diskMust(err)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || filepath.Base(dir) != item.Name {
		panic("unowned fixture directory")
	}
	own, err := os.ReadFile(filepath.Join(dir, ".owned-synthetic-fixture"))
	diskMust(err)
	if !bytes.Equal(own, diskMarker(item)) {
		panic("wrong fixture ownership marker")
	}
	ldb, tree := diskOpenTree(dir)
	defer func() {
		diskMust(ldb.Close())
		diskMust(os.WriteFile(filepath.Join(dir, ".child-clean-close"), []byte("closed\n"), 0o600))
	}()
	trace := []string{"OpenFile", "NewNodeTree"}
	switch item.Boundary {
	case "after-open":
	case "after-stage":
		diskMust(tree.Update(diskPatch(3)))
		trace = append(trace, "Update")
	case "after-commit":
		diskMust(tree.Update(diskPatch(3)))
		trace = append(trace, "Update")
		diskMust(tree.Commit(diskIdentifier("A", 3)))
		trace = append(trace, "Commit")
	case "after-truncate":
		diskMust(tree.Truncate(diskIdentifier("A", 2)))
		trace = append(trace, "Truncate")
	case "after-prune":
		diskMust(tree.Prune(3))
		trace = append(trace, "Prune")
	default:
		panic("unselected operation boundary")
	}
	diskMust(json.NewEncoder(os.Stdout).Encode(map[string]any{"boundary": item.Boundary, "method_trace": trace, "frontier_before_exit": diskIDRecord(tree.FrontierIdentifier())}))
	if item.Name != "clean-close" {
		os.Exit(diskControlledExit)
	}
}
func diskStorageRecord(ldb *leveldb.DB) any {
	counts := map[string]int{"frontier": 0, "node": 0, "refcount": 0, "version": 0, "format": 0}
	kinds := map[byte]string{0: "frontier", 1: "node", 2: "refcount", 3: "version", 5: "format"}
	total, keyBytes, valueBytes := 0, 0, 0
	heights := []uint64{}
	iter := ldb.NewIterator(nil, nil)
	for iter.Next() {
		k, v := iter.Key(), iter.Value()
		if len(k) == 0 {
			panic("empty node store key")
		}
		kind, ok := kinds[k[0]]
		if !ok {
			panic("unknown node store family")
		}
		counts[kind]++
		total++
		keyBytes += len(k)
		valueBytes += len(v)
		if kind == "version" {
			if len(k) != 9 {
				panic("bad retained version key")
			}
			h := uint64(0)
			for _, b := range k[1:] {
				h = h<<8 | uint64(b)
			}
			heights = append(heights, h)
		}
	}
	iter.Release()
	diskMust(iter.Error())
	return map[string]any{"records": total, "key_bytes": keyBytes, "value_bytes": valueBytes, "family_counts": counts, "retained_heights": heights}
}
func diskObserve(dir string, round int) any {
	ldb, tree := diskOpenTree(dir)
	closed := false
	defer func() {
		if !closed {
			ldb.Close()
		}
	}()
	reads := []any{}
	for h := uint64(0); h <= 4; h++ {
		id := diskIdentifier("A", h)
		for _, name := range []string{"root", "root-other-hash", "balance", "absent-token"} {
			target := id
			if name == "root-other-hash" {
				target = diskIdentifier("X", h)
			}
			row := map[string]any{"name": name, "identifier": diskIDRecord(target), "key": nil, "root": nil, "value": nil, "proof": nil, "error": nil}
			if name == "root" || name == "root-other-hash" {
				root, err := tree.Root(target)
				row["root"] = root.String()
				row["error"] = diskNullableError(err)
			} else {
				rawKey := diskKey(name == "absent-token")
				value, proof, err := tree.Prove(target, rawKey)
				row["key"] = hex.EncodeToString(rawKey)
				row["value"] = diskNullableHex(value)
				row["proof"] = diskNullableHex(proof)
				row["error"] = diskNullableError(err)
			}
			reads = append(reads, row)
		}
	}
	row := map[string]any{"round": round, "frontier": diskIDRecord(tree.FrontierIdentifier()), "storage": diskStorageRecord(ldb), "reads": reads}
	diskMust(ldb.Close())
	closed = true
	return row
}
func generateDiskLifecycle() any {
	executable, err := os.Executable()
	diskMust(err)
	rows := []any{}
	for _, item := range diskInputs() {
		temporary, err := os.MkdirTemp("", "candidate-disk-lifecycle-")
		diskMust(err)
		func() {
			defer func() {
				diskMust(os.RemoveAll(temporary))
				if _, err := os.Lstat(temporary); !os.IsNotExist(err) {
					panic("owned temporary fixture was not removed")
				}
			}()
			dir := filepath.Join(temporary, item.Name)
			diskMust(os.Mkdir(dir, 0o700))
			diskMust(os.WriteFile(filepath.Join(dir, ".owned-synthetic-fixture"), diskMarker(item), 0o600))
			diskSeed(dir, item)
			command := exec.Command(executable, "--verified-node-tree", nodeTree, "--disk-child", item.Name, dir)
			var out, diagnostics bytes.Buffer
			command.Stdout = &out
			command.Stderr = &diagnostics
			err := command.Run()
			exit := 0
			if err != nil {
				e, ok := err.(*exec.ExitError)
				if !ok {
					panic(err)
				}
				exit = e.ExitCode()
			}
			expected := diskControlledExit
			if item.Name == "clean-close" {
				expected = 0
			}
			if exit != expected || diagnostics.Len() != 0 {
				panic(fmt.Sprintf("unselected child outcome exit=%d stderr=%q", exit, diagnostics.String()))
			}
			var record any
			diskMust(json.Unmarshal(out.Bytes(), &record))
			_, closeErr := os.Lstat(filepath.Join(dir, ".child-clean-close"))
			closed := closeErr == nil
			if closeErr != nil && !os.IsNotExist(closeErr) {
				panic(closeErr)
			}
			rows = append(rows, map[string]any{"input": item, "child_exit": exit, "child_clean_close_marker": closed, "child_observation": record, "rounds": []any{diskObserve(dir, 1), diskObserve(dir, 2)}})
		}()
	}
	return map[string]any{"format_version": 1, "kind": "candidate-disk-lifecycle-research", "backend": "NodeTree",
		"source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"scope": map[string]bool{"synthetic": true, "unsigned": true, "actual_NodeTree_disk_APIs_executed": true,
			"small_owned_temporary_disk_LevelDB": true, "controlled_process_exit_executed": true,
			"child_defer_close_marker_checked": true, "controlled_clean_close_control": true,
			"controlled_clean_reopen_executed": true, "logical_storage_records_measured": true, "owned_databases_removed": true,
			"chain_component_Init_executed": false, "chain_Start_executed": false, "background_build_executed": false,
			"full_node_started": false, "node_tests_executed": false, "network_execution": false, "RPC_executed": false,
			"signing": false, "transactions": false, "power_loss_qualified": false, "torn_write_qualified": false,
			"production_crash_recovery_qualified": false, "authenticated_retained_version_provenance_qualified": false,
			"realistic_retention_resource_budgets_qualified": false, "header_authentication_executed": false,
			"profile_agreed": false, "network_activation_authenticated": false, "runtime_state_proof_acceptance": false}, "cases": rows}
}
func init() {
	diskLifecycleGenerator = generateDiskLifecycle
	if len(os.Args) > 3 && os.Args[3] == "--disk-child" {
		require(len(os.Args) == 6 && os.Args[1] == "--verified-node-tree" && os.Args[2] == nodeTree, "unselected disk child arguments")
		info, ok := debug.ReadBuildInfo()
		require(ok, "missing disk child build provenance")
		selected := false
		for _, dependency := range info.Deps {
			if dependency.Path == "github.com/zenon-network/go-zenon" {
				selected = dependency.Version == "v0.0.0" && dependency.Replace != nil && dependency.Replace.Path == "../reference-node" && (dependency.Replace.Version == "" || dependency.Replace.Version == "(devel)")
			}
		}
		require(selected, "expected separately verified local candidate disk source")
		for _, item := range diskInputs() {
			if item.Name == os.Args[4] {
				diskChild(item, os.Args[5])
				os.Exit(0)
			}
		}
		panic("unselected disk child fixture")
	}
}
