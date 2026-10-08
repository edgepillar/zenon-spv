//go:build candidate_empty_versions

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
)

type emptyAction struct {
	label, operation, patch string
	height                  int
}

func emptyActions(name string) []emptyAction {
	a := []emptyAction{{"fresh", "observe", "", 0}}
	switch name {
	case "empty-bulk-seed":
		a = append(a,
			emptyAction{"unstaged-bulk", "CommitBulk", "", 3},
			emptyAction{"empty-stage", "Update", "empty", 0},
			emptyAction{"empty-seed", "CommitBulk", "", 3},
			emptyAction{"absent-delete-stage", "Update", "delete-absent", 0},
			emptyAction{"empty-bulk-reuse", "CommitBulk", "", 5},
			emptyAction{"empty-tail-stage", "Update", "empty", 0},
			emptyAction{"empty-regular-tail", "Commit", "", 6},
			emptyAction{"prune-empty-seeds", "Prune", "", 6})
	case "delete-all-and-reinsert":
		a = append(a,
			emptyAction{"complete-stage", "Update", "complete", 0},
			emptyAction{"complete-seed", "CommitBulk", "", 3},
			emptyAction{"delete-all-stage", "Update", "delete-all", 0},
			emptyAction{"delete-all-tail", "Commit", "", 4},
			emptyAction{"empty-stage", "Update", "empty", 0},
			emptyAction{"empty-bulk-reuse", "CommitBulk", "", 6},
			emptyAction{"prune-last-nonempty", "Prune", "", 4},
			emptyAction{"empty-clean-reopen", "reopen", "", 0},
			emptyAction{"reinsert-stage", "Update", "reinsert", 0},
			emptyAction{"reinsert-tail", "Commit", "", 7},
			emptyAction{"prune-empty-versions", "Prune", "", 7})
	case "last-zero-delete":
		a = append(a,
			emptyAction{"zero-stage", "Update", "single-zero", 0},
			emptyAction{"zero-seed", "CommitBulk", "", 3},
			emptyAction{"absent-delete-stage", "Update", "delete-absent", 0},
			emptyAction{"zero-no-op-tail", "Commit", "", 4},
			emptyAction{"last-zero-delete-stage", "Update", "delete-zero", 0},
			emptyAction{"last-zero-delete-bulk", "CommitBulk", "", 6},
			emptyAction{"prune-shared-last-leaf", "Prune", "", 6},
			emptyAction{"empty-clean-reopen", "reopen", "", 0},
			emptyAction{"zero-reinsert-stage", "Update", "single-zero", 0},
			emptyAction{"zero-reinsert-tail", "Commit", "", 7},
			emptyAction{"prune-empty-version", "Prune", "", 7})
	default:
		panic("unselected empty-version fixture")
	}
	return a
}

func emptyMust(err error) {
	if err != nil {
		panic(err)
	}
}
func emptyIdentifier(name string, height int) types.HashHeight {
	if height == 0 {
		return types.ZeroHashHeight
	}
	return types.HashHeight{Height: uint64(height), Hash: types.NewHash([]byte(fmt.Sprintf("synthetic-empty-versions-v1/%s/A/%d", name, height)))}
}
func emptyIDRecord(value types.HashHeight) any {
	return map[string]any{"height": value.Height, "hash": value.Hash.String()}
}
func emptyKey(index int) []byte {
	address := bytes.Repeat([]byte{0x11}, 20)
	binary.BigEndian.PutUint32(address[16:], uint32(index))
	return append(append(append([]byte{3}, address...), 3), bytes.Repeat([]byte{0x22}, 10)...)
}
func emptyValue(amount uint64) []byte {
	value := make([]byte, 32)
	binary.BigEndian.PutUint64(value[24:], amount)
	return value
}
func emptyCompleteMap() map[int][]byte {
	state := map[int][]byte{}
	for i := 0; i < 8; i++ {
		amount := uint64(i + 1)
		if i == 0 {
			amount = 0
		}
		state[i] = emptyValue(amount)
	}
	return state
}
func emptyPatch(name string) db.Patch {
	p := db.NewPatch()
	switch name {
	case "complete":
		for i := 0; i < 8; i++ {
			p.Put(emptyKey(i), emptyCompleteMap()[i])
		}
	case "delete-all":
		for i := 0; i < 8; i++ {
			p.Delete(emptyKey(i))
		}
	case "delete-absent":
		p.Delete(emptyKey(8))
	case "delete-zero":
		p.Delete(emptyKey(0))
	case "single-zero":
		p.Put(emptyKey(0), emptyValue(0))
	case "reinsert":
		p.Put(emptyKey(0), emptyValue(0))
		p.Put(emptyKey(1), emptyValue(91))
	case "empty":
	default:
		panic("unselected empty-version patch")
	}
	return p
}

// This complete fixture is described separately from the observed database.
// It does not authenticate a network snapshot or retained Momentum hash.
func emptySelected(name string) map[int][]byte {
	switch name {
	case "empty-bulk-seed":
		return map[int][]byte{}
	case "delete-all-and-reinsert":
		return map[int][]byte{0: emptyValue(0), 1: emptyValue(91)}
	case "last-zero-delete":
		return map[int][]byte{0: emptyValue(0)}
	default:
		panic("unselected empty-version final map")
	}
}
func emptySelectedRoot(state map[int][]byte) (types.Hash, any) {
	indices := []int{}
	for index := range state {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	paths, values := []trie.Path{}, [][]byte{}
	digest := sha256.New()
	width := make([]byte, 8)
	for _, index := range indices {
		key, value := emptyKey(index), state[index]
		paths, values = append(paths, trie.Path(types.NewHash(key))), append(values, value)
		binary.BigEndian.PutUint64(width, uint64(len(key)))
		digest.Write(width)
		digest.Write(key)
		binary.BigEndian.PutUint64(width, uint64(len(value)))
		digest.Write(width)
		digest.Write(value)
	}
	root, err := trie.RootOfLeaves(paths, values)
	emptyMust(err)
	return root, map[string]any{"present_keys": len(state), "raw_map_sha256": hex.EncodeToString(digest.Sum(nil))}
}
func emptyStorage(ldb *leveldb.DB) any {
	counts := map[string]int{"frontier": 0, "node": 0, "refcount": 0, "version": 0, "format": 0}
	families := map[byte]string{0: "frontier", 1: "node", 2: "refcount", 3: "version", 5: "format"}
	digest := sha256.New()
	records, keyBytes, valueBytes := 0, 0, 0
	heights := []uint64{}
	width := make([]byte, 8)
	iter := ldb.NewIterator(nil, nil)
	for iter.Next() {
		k, v := iter.Key(), iter.Value()
		require(len(k) > 0, "empty empty store key")
		family, ok := families[k[0]]
		require(ok, "unknown empty store family")
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
			require(len(k) == 9, "wrong empty version key")
			heights = append(heights, binary.BigEndian.Uint64(k[1:]))
		}
	}
	iter.Release()
	emptyMust(iter.Error())
	return map[string]any{"records": records, "key_bytes": keyBytes, "value_bytes": valueBytes, "family_counts": counts, "retained_heights": heights, "records_sha256": hex.EncodeToString(digest.Sum(nil))}
}
func emptyNullableBytes(value []byte) any {
	if value == nil {
		return nil
	}
	return hex.EncodeToString(value)
}
func emptyNullableError(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}
func emptyObserve(name string, action emptyAction, err error, tree *trie.NodeTree, ldb *leveldb.DB) any {
	rows := []any{}
	for height := 0; height < 8; height++ {
		for _, index := range []int{-1, 0, 1, 2, 8} {
			row := map[string]any{"identifier": emptyIDRecord(emptyIdentifier(name, height)), "key": nil, "root": nil, "value": nil, "proof": nil, "error": nil}
			if index == -1 {
				root, failure := tree.Root(emptyIdentifier(name, height))
				row["root"], row["error"] = root.String(), emptyNullableError(failure)
			} else {
				key := emptyKey(index)
				value, proof, failure := tree.Prove(emptyIdentifier(name, height), key)
				row["key"], row["value"], row["proof"], row["error"] = hex.EncodeToString(key), emptyNullableBytes(value), emptyNullableBytes(proof), emptyNullableError(failure)
			}
			rows = append(rows, row)
		}
	}
	var patch, height any
	if action.patch != "" {
		patch = action.patch
	}
	if action.operation == "Commit" || action.operation == "CommitBulk" || action.operation == "Prune" {
		height = action.height
	}
	return map[string]any{"label": action.label, "operation": action.operation, "patch": patch, "target_height": height, "operation_error": emptyNullableError(err), "frontier": emptyIDRecord(tree.FrontierIdentifier()), "storage": emptyStorage(ldb), "reads": rows}
}
func emptyOpen(dir string) (*leveldb.DB, *trie.NodeTree) {
	ldb, err := leveldb.OpenFile(dir, nil)
	emptyMust(err)
	tree, err := trie.NewNodeTree(ldb)
	if err != nil {
		ldb.Close()
		panic(err)
	}
	return ldb, tree
}
func emptyCase(name, dir string) any {
	ldb, tree := emptyOpen(dir)
	defer func() { emptyMust(ldb.Close()) }()
	steps := []any{}
	for _, action := range emptyActions(name) {
		var err error
		switch action.operation {
		case "observe":
		case "Update":
			err = tree.Update(emptyPatch(action.patch))
		case "reopen":
			emptyMust(ldb.Close())
			ldb, tree = emptyOpen(dir)
		case "Commit":
			err = tree.Commit(emptyIdentifier(name, action.height))
		case "CommitBulk":
			err = tree.CommitBulk(emptyIdentifier(name, action.height))
		case "Prune":
			err = tree.Prune(uint64(action.height))
		default:
			panic("unselected empty operation")
		}
		steps = append(steps, emptyObserve(name, action, err, tree, ldb))
	}
	emptyMust(ldb.Close())
	ldb, tree = emptyOpen(dir)
	steps = append(steps, emptyObserve(name, emptyAction{"clean-reopen", "reopen", "", 0}, nil, tree, ldb))
	emptyMust(ldb.CompactRange(util.Range{}))
	emptyMust(ldb.Close())
	ldb, tree = emptyOpen(dir)
	steps = append(steps, emptyObserve(name, emptyAction{"compacted-clean-reopen", "compact-reopen", "", 0}, nil, tree, ldb))
	selectedRoot, manifest := emptySelectedRoot(emptySelected(name))
	identifier := tree.FrontierIdentifier()
	observedRoot, err := tree.Root(identifier)
	emptyMust(err)
	checks := []any{}
	for _, index := range []int{0, 1, 2, 8} {
		key := emptyKey(index)
		value, proof, err := tree.Prove(identifier, key)
		emptyMust(err)
		p := proofCase{Path: types.NewHash(key).String(), Value: hex.EncodeToString(value), Proof: hex.EncodeToString(proof), Present: value != nil, Root: observedRoot.String()}
		own := nodeResult(p)
		p.Root = selectedRoot.String()
		checks = append(checks, map[string]any{"key": hex.EncodeToString(key), "value": emptyNullableBytes(value), "proof": hex.EncodeToString(proof), "own_root_result": own, "selected_fixture_result": nodeResult(p)})
	}
	return map[string]any{"name": name, "steps": steps, "boundary": map[string]any{"identifier": emptyIDRecord(identifier), "selected_fixture_root": selectedRoot.String(), "selected_fixture_manifest": manifest, "observed_root": observedRoot.String(), "root_matches_selected_fixture": observedRoot == selectedRoot, "proof_checks": checks}}
}
func generateEmptyVersions() any {
	cases := []any{}
	for _, name := range []string{"empty-bulk-seed", "delete-all-and-reinsert", "last-zero-delete"} {
		func() {
			temporary, err := os.MkdirTemp("", "candidate-empty-versions-")
			emptyMust(err)
			defer func() { emptyMust(os.RemoveAll(temporary)) }()
			cases = append(cases, emptyCase(name, filepath.Join(temporary, "owned-tree")))
		}()
	}
	return map[string]any{"format_version": 1, "kind": "candidate-empty-versions-research", "backend": "NodeTree", "source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"scope": map[string]bool{"synthetic": true, "unsigned": true, "actual_NodeTree_disk_APIs_executed": true, "actual_NodeTree_CommitBulk_executed": true, "actual_NodeTree_AccumulateFrom_executed": false, "single_serial_caller_for_staged_sequence": true, "small_owned_temporary_disk_LevelDB": true, "controlled_clean_reopen_executed": true, "manual_compaction_executed": true, "logical_storage_records_measured": true, "owned_databases_removed": true, "selected_fixture_not_authenticated_snapshot": true, "resource_measurements_executed": false, "chain_component_Init_executed": false, "chain_Start_executed": false, "background_build_executed": false, "full_node_started": false, "node_tests_executed": false, "network_execution": false, "RPC_executed": false, "signing": false, "transactions": false, "power_loss_qualified": false, "production_crash_recovery_qualified": false, "authenticated_retained_version_provenance_qualified": false, "realistic_retention_resource_budgets_qualified": false, "profile_agreed": false, "network_activation_authenticated": false, "runtime_state_proof_acceptance": false}, "cases": cases}
}
func init() { emptyVersionsGenerator = generateEmptyVersions }
