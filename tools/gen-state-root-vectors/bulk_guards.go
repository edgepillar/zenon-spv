//go:build candidate_bulk_guards

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

type guardAction struct {
	label, operation, patch string
	height                  int
}

func guardActions(name string) []guardAction {
	a := []guardAction{{"fresh", "observe", "", 0}}
	switch name {
	case "guards-and-shared-root":
		a = append(a,
			guardAction{"unstaged-bulk", "CommitBulk", "", 3},
			guardAction{"empty-stage", "Update", "empty", 0},
			guardAction{"origin-bulk-refused", "CommitBulk", "", 0},
			guardAction{"replace-with-complete-seed", "Update", "complete", 0},
			guardAction{"regular-gap-refused", "Commit", "", 3},
			guardAction{"retry-seed-as-bulk", "CommitBulk", "", 3},
			guardAction{"consumed-bulk-stage", "CommitBulk", "", 4},
			guardAction{"empty-reuse-stage", "Update", "empty", 0},
			guardAction{"same-height-refused", "CommitBulk", "", 3},
			guardAction{"backward-height-refused", "CommitBulk", "", 2},
			guardAction{"retry-empty-bulk", "CommitBulk", "", 5},
			guardAction{"consumed-regular-stage", "Commit", "", 6},
			guardAction{"empty-tail-stage", "Update", "empty", 0},
			guardAction{"regular-no-op-tail", "Commit", "", 6},
			guardAction{"prune-shared-roots", "Prune", "", 6})
	case "accumulated-zero-delete-reinsert":
		a = append(a,
			guardAction{"accumulate-complete", "AccumulateFrom", "complete", 0},
			guardAction{"accumulate-delete-zero", "AccumulateFrom", "fold-two", 0},
			guardAction{"accumulate-reinsert", "AccumulateFrom", "fold-three", 0},
			guardAction{"commit-folded-seed", "CommitBulk", "", 3},
			guardAction{"tail-delete-zero", "Update", "tail-four", 0},
			guardAction{"commit-tail", "Commit", "", 4},
			guardAction{"empty-fold-stage", "Update", "empty", 0},
			guardAction{"shared-folded-root", "CommitBulk", "", 6},
			guardAction{"prune-old-seed", "Prune", "", 4},
			guardAction{"prune-shared-tail", "Prune", "", 6})
	case "omitted-seed-zero":
		a = append(a,
			guardAction{"incomplete-zero-stage", "Update", "without-zero", 0},
			guardAction{"commit-incomplete-zero", "CommitBulk", "", 3},
			guardAction{"incomplete-no-op-stage", "Update", "empty", 0},
			guardAction{"reuse-incomplete-root", "CommitBulk", "", 5},
			guardAction{"prune-incomplete-seed", "Prune", "", 5})
	case "omitted-accumulated-delete":
		a = append(a,
			guardAction{"complete-base-stage", "Update", "complete", 0},
			guardAction{"complete-base", "CommitBulk", "", 3},
			guardAction{"incomplete-delete-stage", "AccumulateFrom", "without-delete", 0},
			guardAction{"commit-incomplete-delete", "CommitBulk", "", 5},
			guardAction{"prune-complete-base", "Prune", "", 5})
	default:
		panic("unselected bulk guard fixture")
	}
	return a
}

func guardMust(err error) {
	if err != nil {
		panic(err)
	}
}
func guardIdentifier(name string, height int) types.HashHeight {
	if height == 0 {
		return types.ZeroHashHeight
	}
	return types.HashHeight{Height: uint64(height), Hash: types.NewHash([]byte(fmt.Sprintf("synthetic-bulk-guards-v1/%s/A/%d", name, height)))}
}
func guardIDRecord(value types.HashHeight) any {
	return map[string]any{"height": value.Height, "hash": value.Hash.String()}
}
func guardKey(index int) []byte {
	address := bytes.Repeat([]byte{0x11}, 20)
	binary.BigEndian.PutUint32(address[16:], uint32(index))
	return append(append(append([]byte{3}, address...), 3), bytes.Repeat([]byte{0x22}, 10)...)
}
func guardValue(amount uint64) []byte {
	value := make([]byte, 32)
	binary.BigEndian.PutUint64(value[24:], amount)
	return value
}
func guardCompleteMap() map[int][]byte {
	state := map[int][]byte{}
	for i := 0; i < 8; i++ {
		amount := uint64(i + 1)
		if i == 0 {
			amount = 0
		}
		state[i] = guardValue(amount)
	}
	return state
}
func guardPatch(name string) db.Patch {
	p := db.NewPatch()
	switch name {
	case "complete", "without-zero":
		state := guardCompleteMap()
		for i := 0; i < 8; i++ {
			if name == "without-zero" && i == 0 {
				continue
			}
			p.Put(guardKey(i), state[i])
		}
	case "fold-two":
		p.Put(guardKey(1), guardValue(17))
		p.Delete(guardKey(2))
		p.Put(guardKey(3), guardValue(0))
		p.Delete(guardKey(7))
	case "fold-three":
		p.Delete(guardKey(1))
		p.Put(guardKey(2), guardValue(22))
		p.Put(guardKey(7), guardValue(0))
	case "tail-four":
		p.Delete(guardKey(0))
		p.Put(guardKey(1), guardValue(0))
		p.Put(guardKey(7), guardValue(47))
	case "without-delete":
		p.Put(guardKey(1), guardValue(0))
	case "empty":
	default:
		panic("unselected guard patch")
	}
	return p
}

// This selected complete fixture map is described separately from the observed
// database. It is an offline oracle input, not an authenticated network root.
func guardSelected(name string) map[int][]byte {
	state := guardCompleteMap()
	switch name {
	case "accumulated-zero-delete-reinsert":
		delete(state, 0)
		state[1], state[2], state[3], state[7] = guardValue(0), guardValue(22), guardValue(0), guardValue(47)
	case "omitted-accumulated-delete":
		state[1] = guardValue(0)
		delete(state, 2)
	}
	return state
}
func guardSelectedRoot(state map[int][]byte) (types.Hash, any) {
	indices := []int{}
	for index := range state {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	paths, values := []trie.Path{}, [][]byte{}
	digest := sha256.New()
	width := make([]byte, 8)
	for _, index := range indices {
		key, value := guardKey(index), state[index]
		paths, values = append(paths, trie.Path(types.NewHash(key))), append(values, value)
		binary.BigEndian.PutUint64(width, uint64(len(key)))
		digest.Write(width)
		digest.Write(key)
		binary.BigEndian.PutUint64(width, uint64(len(value)))
		digest.Write(width)
		digest.Write(value)
	}
	root, err := trie.RootOfLeaves(paths, values)
	guardMust(err)
	return root, map[string]any{"present_keys": len(state), "raw_map_sha256": hex.EncodeToString(digest.Sum(nil))}
}
func guardStorage(ldb *leveldb.DB) any {
	counts := map[string]int{"frontier": 0, "node": 0, "refcount": 0, "version": 0, "format": 0}
	families := map[byte]string{0: "frontier", 1: "node", 2: "refcount", 3: "version", 5: "format"}
	digest := sha256.New()
	records, keyBytes, valueBytes := 0, 0, 0
	heights := []uint64{}
	width := make([]byte, 8)
	iter := ldb.NewIterator(nil, nil)
	for iter.Next() {
		k, v := iter.Key(), iter.Value()
		require(len(k) > 0, "empty guard store key")
		family, ok := families[k[0]]
		require(ok, "unknown guard store family")
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
			require(len(k) == 9, "wrong guard version key")
			heights = append(heights, binary.BigEndian.Uint64(k[1:]))
		}
	}
	iter.Release()
	guardMust(iter.Error())
	return map[string]any{"records": records, "key_bytes": keyBytes, "value_bytes": valueBytes, "family_counts": counts, "retained_heights": heights, "records_sha256": hex.EncodeToString(digest.Sum(nil))}
}
func guardNullableBytes(value []byte) any {
	if value == nil {
		return nil
	}
	return hex.EncodeToString(value)
}
func guardNullableError(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}
func guardObserve(name string, action guardAction, err error, tree *trie.NodeTree, ldb *leveldb.DB) any {
	rows := []any{}
	for height := 0; height < 8; height++ {
		for _, index := range []int{-1, 0, 1, 2, 8} {
			row := map[string]any{"identifier": guardIDRecord(guardIdentifier(name, height)), "key": nil, "root": nil, "value": nil, "proof": nil, "error": nil}
			if index == -1 {
				root, failure := tree.Root(guardIdentifier(name, height))
				row["root"], row["error"] = root.String(), guardNullableError(failure)
			} else {
				key := guardKey(index)
				value, proof, failure := tree.Prove(guardIdentifier(name, height), key)
				row["key"], row["value"], row["proof"], row["error"] = hex.EncodeToString(key), guardNullableBytes(value), guardNullableBytes(proof), guardNullableError(failure)
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
	return map[string]any{"label": action.label, "operation": action.operation, "patch": patch, "target_height": height, "operation_error": guardNullableError(err), "frontier": guardIDRecord(tree.FrontierIdentifier()), "storage": guardStorage(ldb), "reads": rows}
}
func guardOpen(dir string) (*leveldb.DB, *trie.NodeTree) {
	ldb, err := leveldb.OpenFile(dir, nil)
	guardMust(err)
	tree, err := trie.NewNodeTree(ldb)
	if err != nil {
		ldb.Close()
		panic(err)
	}
	return ldb, tree
}
func guardCase(name, dir string) any {
	ldb, tree := guardOpen(dir)
	defer func() { guardMust(ldb.Close()) }()
	steps := []any{}
	for _, action := range guardActions(name) {
		var err error
		switch action.operation {
		case "observe":
		case "Update":
			err = tree.Update(guardPatch(action.patch))
		case "AccumulateFrom":
			err = tree.AccumulateFrom(guardPatch(action.patch))
		case "Commit":
			err = tree.Commit(guardIdentifier(name, action.height))
		case "CommitBulk":
			err = tree.CommitBulk(guardIdentifier(name, action.height))
		case "Prune":
			err = tree.Prune(uint64(action.height))
		default:
			panic("unselected guard operation")
		}
		steps = append(steps, guardObserve(name, action, err, tree, ldb))
	}
	guardMust(ldb.Close())
	ldb, tree = guardOpen(dir)
	steps = append(steps, guardObserve(name, guardAction{"clean-reopen", "reopen", "", 0}, nil, tree, ldb))
	guardMust(ldb.CompactRange(util.Range{}))
	guardMust(ldb.Close())
	ldb, tree = guardOpen(dir)
	steps = append(steps, guardObserve(name, guardAction{"compacted-clean-reopen", "compact-reopen", "", 0}, nil, tree, ldb))
	selectedRoot, manifest := guardSelectedRoot(guardSelected(name))
	identifier := tree.FrontierIdentifier()
	observedRoot, err := tree.Root(identifier)
	guardMust(err)
	checks := []any{}
	for _, index := range []int{0, 1, 2, 8} {
		key := guardKey(index)
		value, proof, err := tree.Prove(identifier, key)
		guardMust(err)
		p := proofCase{Path: types.NewHash(key).String(), Value: hex.EncodeToString(value), Proof: hex.EncodeToString(proof), Present: value != nil, Root: observedRoot.String()}
		own := nodeResult(p)
		p.Root = selectedRoot.String()
		checks = append(checks, map[string]any{"key": hex.EncodeToString(key), "value": guardNullableBytes(value), "proof": hex.EncodeToString(proof), "own_root_result": own, "selected_complete_fixture_result": nodeResult(p)})
	}
	return map[string]any{"name": name, "steps": steps, "boundary": map[string]any{"identifier": guardIDRecord(identifier), "selected_complete_fixture_root": selectedRoot.String(), "selected_complete_fixture_manifest": manifest, "observed_root": observedRoot.String(), "root_matches_selected_complete_fixture": observedRoot == selectedRoot, "proof_checks": checks}}
}
func generateBulkGuards() any {
	cases := []any{}
	for _, name := range []string{"guards-and-shared-root", "accumulated-zero-delete-reinsert", "omitted-seed-zero", "omitted-accumulated-delete"} {
		func() {
			temporary, err := os.MkdirTemp("", "candidate-bulk-guards-")
			guardMust(err)
			defer func() { guardMust(os.RemoveAll(temporary)) }()
			cases = append(cases, guardCase(name, filepath.Join(temporary, "owned-tree")))
		}()
	}
	return map[string]any{"format_version": 1, "kind": "candidate-bulk-guards-research", "backend": "NodeTree", "source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"scope": map[string]bool{"synthetic": true, "unsigned": true, "actual_NodeTree_disk_APIs_executed": true, "actual_NodeTree_CommitBulk_executed": true, "actual_NodeTree_AccumulateFrom_executed": true, "single_serial_caller_for_staged_sequence": true, "small_owned_temporary_disk_LevelDB": true, "controlled_clean_reopen_executed": true, "manual_compaction_executed": true, "logical_storage_records_measured": true, "owned_databases_removed": true, "selected_complete_fixture_not_authenticated_snapshot": true, "resource_measurements_executed": false, "chain_component_Init_executed": false, "chain_Start_executed": false, "background_build_executed": false, "full_node_started": false, "node_tests_executed": false, "network_execution": false, "RPC_executed": false, "signing": false, "transactions": false, "power_loss_qualified": false, "production_crash_recovery_qualified": false, "authenticated_retained_version_provenance_qualified": false, "realistic_retention_resource_budgets_qualified": false, "profile_agreed": false, "network_activation_authenticated": false, "runtime_state_proof_acceptance": false}, "cases": cases}
}
func init() { bulkGuardsGenerator = generateBulkGuards }
