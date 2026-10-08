//go:build candidate_height_boundary

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

type heightAction struct {
	label, operation, patch string
	height                  uint64
}

const heightMaximum uint64 = ^uint64(0)

func heightActions(name string) []heightAction {
	a := []heightAction{{"fresh", "observe", "", 0}}
	switch name {
	case "bulk-max-wrap-tail":
		a = append(a,
			heightAction{"complete-stage", "Update", "complete", 0},
			heightAction{"maximum-bulk", "CommitBulk", "", heightMaximum},
			heightAction{"changes-stage", "Update", "changes", 0},
			heightAction{"regular-one-refused", "Commit", "", 1},
			heightAction{"bulk-origin-refused", "CommitBulk", "", 0},
			heightAction{"bulk-maximum-refused", "CommitBulk", "", heightMaximum},
			heightAction{"regular-origin-wrap", "Commit", "", 0},
			heightAction{"wrapped-clean-reopen", "reopen", "", 0},
			heightAction{"tail-stage", "Update", "tail", 0},
			heightAction{"regular-one-after-wrap", "Commit", "", 1})
	case "regular-max-wrap":
		a = append(a,
			heightAction{"complete-stage", "Update", "complete", 0},
			heightAction{"before-maximum-bulk", "CommitBulk", "", heightMaximum - 1},
			heightAction{"changes-stage", "Update", "changes", 0},
			heightAction{"maximum-regular", "Commit", "", heightMaximum},
			heightAction{"empty-stage", "Update", "empty", 0},
			heightAction{"regular-origin-wrap", "Commit", "", 0})
	case "empty-max-wrap":
		a = append(a,
			heightAction{"empty-stage", "Update", "empty", 0},
			heightAction{"maximum-bulk", "CommitBulk", "", heightMaximum},
			heightAction{"empty-wrap-stage", "Update", "empty", 0},
			heightAction{"regular-origin-wrap", "Commit", "", 0})
	default:
		panic("unselected height-boundary fixture")
	}
	return a
}

func heightMust(err error) {
	if err != nil {
		panic(err)
	}
}
func heightIdentifier(name string, height uint64) types.HashHeight {
	if height == 0 {
		return types.ZeroHashHeight
	}
	return types.HashHeight{Height: height, Hash: types.NewHash([]byte(fmt.Sprintf("synthetic-height-boundary-v1/%s/A/%d", name, height)))}
}
func heightIDRecord(value types.HashHeight) any {
	return map[string]any{"height": value.Height, "hash": value.Hash.String()}
}
func heightKey(index int) []byte {
	address := bytes.Repeat([]byte{0x11}, 20)
	binary.BigEndian.PutUint32(address[16:], uint32(index))
	return append(append(append([]byte{3}, address...), 3), bytes.Repeat([]byte{0x22}, 10)...)
}
func heightValue(amount uint64) []byte {
	value := make([]byte, 32)
	binary.BigEndian.PutUint64(value[24:], amount)
	return value
}
func heightCompleteMap() map[int][]byte {
	state := map[int][]byte{}
	for i := 0; i < 8; i++ {
		amount := uint64(i + 1)
		if i == 0 {
			amount = 0
		}
		state[i] = heightValue(amount)
	}
	return state
}
func heightPatch(name string) db.Patch {
	p := db.NewPatch()
	switch name {
	case "complete":
		for i := 0; i < 8; i++ {
			p.Put(heightKey(i), heightCompleteMap()[i])
		}
	case "changes":
		p.Put(heightKey(1), heightValue(91))
		p.Delete(heightKey(2))
	case "tail":
		p.Put(heightKey(8), heightValue(9))
	case "empty":
	default:
		panic("unselected height-boundary patch")
	}
	return p
}

// The intended monotonic state is selected independently from observed reads.
// Accepted origin wrap is a low-level counterexample, not a production exploit.
// It does not authenticate a network snapshot or retained Momentum hash.
func heightSelected(name string) map[int][]byte {
	if name == "empty-max-wrap" {
		return map[int][]byte{}
	}
	state := heightCompleteMap()
	state[1] = heightValue(91)
	delete(state, 2)
	if name == "bulk-max-wrap-tail" {
		state[8] = heightValue(9)
	}
	return state
}

func heightSelectedRoot(state map[int][]byte) (types.Hash, any) {
	indices := []int{}
	for index := range state {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	paths, values := []trie.Path{}, [][]byte{}
	digest := sha256.New()
	width := make([]byte, 8)
	for _, index := range indices {
		key, value := heightKey(index), state[index]
		paths, values = append(paths, trie.Path(types.NewHash(key))), append(values, value)
		binary.BigEndian.PutUint64(width, uint64(len(key)))
		digest.Write(width)
		digest.Write(key)
		binary.BigEndian.PutUint64(width, uint64(len(value)))
		digest.Write(width)
		digest.Write(value)
	}
	root, err := trie.RootOfLeaves(paths, values)
	heightMust(err)
	return root, map[string]any{"present_keys": len(state), "raw_map_sha256": hex.EncodeToString(digest.Sum(nil))}
}
func heightStorage(ldb *leveldb.DB) any {
	counts := map[string]int{"frontier": 0, "node": 0, "refcount": 0, "version": 0, "format": 0}
	families := map[byte]string{0: "frontier", 1: "node", 2: "refcount", 3: "version", 5: "format"}
	digest := sha256.New()
	records, keyBytes, valueBytes := 0, 0, 0
	heights := []uint64{}
	width := make([]byte, 8)
	iter := ldb.NewIterator(nil, nil)
	for iter.Next() {
		k, v := iter.Key(), iter.Value()
		require(len(k) > 0, "empty height-boundary store key")
		family, ok := families[k[0]]
		require(ok, "unknown height-boundary store family")
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
			require(len(k) == 9, "wrong height version key")
			heights = append(heights, binary.BigEndian.Uint64(k[1:]))
		}
	}
	iter.Release()
	heightMust(iter.Error())
	return map[string]any{"records": records, "key_bytes": keyBytes, "value_bytes": valueBytes, "family_counts": counts, "retained_heights": heights, "records_sha256": hex.EncodeToString(digest.Sum(nil))}
}
func heightNullableBytes(value []byte) any {
	if value == nil {
		return nil
	}
	return hex.EncodeToString(value)
}
func heightNullableError(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}
func heightObserve(name string, action heightAction, err error, tree *trie.NodeTree, ldb *leveldb.DB) any {
	rows := []any{}
	for _, height := range []uint64{0, 1, heightMaximum - 1, heightMaximum} {
		for _, index := range []int{-1, 0, 1, 2, 8} {
			row := map[string]any{"identifier": heightIDRecord(heightIdentifier(name, height)), "key": nil, "root": nil, "value": nil, "proof": nil, "error": nil}
			if index == -1 {
				root, failure := tree.Root(heightIdentifier(name, height))
				row["root"], row["error"] = root.String(), heightNullableError(failure)
			} else {
				key := heightKey(index)
				value, proof, failure := tree.Prove(heightIdentifier(name, height), key)
				row["key"], row["value"], row["proof"], row["error"] = hex.EncodeToString(key), heightNullableBytes(value), heightNullableBytes(proof), heightNullableError(failure)
			}
			rows = append(rows, row)
		}
	}
	var patch, height any
	if action.patch != "" {
		patch = action.patch
	}
	if action.operation == "Commit" || action.operation == "CommitBulk" {
		height = action.height
	}
	return map[string]any{"label": action.label, "operation": action.operation, "patch": patch, "target_height": height, "operation_error": heightNullableError(err), "frontier": heightIDRecord(tree.FrontierIdentifier()), "storage": heightStorage(ldb), "reads": rows}
}
func heightOpen(dir string) (*leveldb.DB, *trie.NodeTree) {
	ldb, err := leveldb.OpenFile(dir, nil)
	heightMust(err)
	tree, err := trie.NewNodeTree(ldb)
	if err != nil {
		ldb.Close()
		panic(err)
	}
	return ldb, tree
}
func heightCase(name, dir string) any {
	ldb, tree := heightOpen(dir)
	defer func() { heightMust(ldb.Close()) }()
	steps := []any{}
	for _, action := range heightActions(name) {
		var err error
		switch action.operation {
		case "observe":
		case "Update":
			err = tree.Update(heightPatch(action.patch))
		case "reopen":
			heightMust(ldb.Close())
			ldb, tree = heightOpen(dir)
		case "Commit":
			err = tree.Commit(heightIdentifier(name, action.height))
		case "CommitBulk":
			err = tree.CommitBulk(heightIdentifier(name, action.height))
		default:
			panic("unselected height operation")
		}
		steps = append(steps, heightObserve(name, action, err, tree, ldb))
	}
	heightMust(ldb.Close())
	ldb, tree = heightOpen(dir)
	steps = append(steps, heightObserve(name, heightAction{"clean-reopen", "reopen", "", 0}, nil, tree, ldb))
	heightMust(ldb.CompactRange(util.Range{}))
	heightMust(ldb.Close())
	ldb, tree = heightOpen(dir)
	steps = append(steps, heightObserve(name, heightAction{"compacted-clean-reopen", "compact-reopen", "", 0}, nil, tree, ldb))
	selectedRoot, manifest := heightSelectedRoot(heightSelected(name))
	identifier := tree.FrontierIdentifier()
	observedRoot, err := tree.Root(identifier)
	heightMust(err)
	checks := []any{}
	for _, index := range []int{0, 1, 2, 8} {
		key := heightKey(index)
		value, proof, err := tree.Prove(identifier, key)
		heightMust(err)
		p := proofCase{Path: types.NewHash(key).String(), Value: hex.EncodeToString(value), Proof: hex.EncodeToString(proof), Present: value != nil, Root: observedRoot.String()}
		own := nodeResult(p)
		p.Root = selectedRoot.String()
		checks = append(checks, map[string]any{"key": hex.EncodeToString(key), "value": heightNullableBytes(value), "proof": hex.EncodeToString(proof), "own_root_result": own, "selected_fixture_result": nodeResult(p)})
	}
	return map[string]any{"name": name, "steps": steps, "boundary": map[string]any{"identifier": heightIDRecord(identifier), "selected_fixture_root": selectedRoot.String(), "selected_fixture_manifest": manifest, "observed_root": observedRoot.String(), "root_matches_selected_fixture": observedRoot == selectedRoot, "monotonic_sequence_qualified": false, "consumer_result": "REFUSED", "proof_checks": checks}}
}
func generateHeightBoundary() any {
	cases := []any{}
	for _, name := range []string{"bulk-max-wrap-tail", "regular-max-wrap", "empty-max-wrap"} {
		func() {
			temporary, err := os.MkdirTemp("", "candidate-height-boundary-")
			heightMust(err)
			defer func() { heightMust(os.RemoveAll(temporary)) }()
			cases = append(cases, heightCase(name, filepath.Join(temporary, "owned-tree")))
		}()
	}
	return map[string]any{"format_version": 1, "kind": "candidate-height-boundary-research", "backend": "NodeTree", "source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"scope": map[string]bool{"synthetic": true, "unsigned": true, "actual_NodeTree_disk_APIs_executed": true, "actual_NodeTree_CommitBulk_executed": true, "actual_NodeTree_AccumulateFrom_executed": false, "no_height_gap_iteration": true, "production_height_reachability_qualified": false, "single_serial_caller_for_staged_sequence": true, "small_owned_temporary_disk_LevelDB": true, "controlled_clean_reopen_executed": true, "manual_compaction_executed": true, "logical_storage_records_measured": true, "owned_databases_removed": true, "selected_fixture_not_authenticated_snapshot": true, "resource_measurements_executed": false, "chain_component_Init_executed": false, "chain_Start_executed": false, "background_build_executed": false, "full_node_started": false, "node_tests_executed": false, "network_execution": false, "RPC_executed": false, "signing": false, "transactions": false, "power_loss_qualified": false, "production_crash_recovery_qualified": false, "authenticated_retained_version_provenance_qualified": false, "realistic_retention_resource_budgets_qualified": false, "profile_agreed": false, "network_activation_authenticated": false, "runtime_state_proof_acceptance": false}, "cases": cases}
}
func init() { heightBoundaryGenerator = generateHeightBoundary }
