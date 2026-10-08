//go:build candidate_staging_boundary

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
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

type stagingAction struct {
	label, operation, patch string
	height                  uint64
	faultAfter              int
}

func stagingAct(label, operation, patch string, height uint64, faultAfter int) stagingAction {
	return stagingAction{label, operation, patch, height, faultAfter}
}
func stagingActions(name string) []stagingAction {
	a := []stagingAction{stagingAct("fresh", "observe", "", 0, -1)}
	switch name {
	case "update-error-keeps-prior-stage":
		a = append(a, stagingAct("complete-stage", "Update", "complete", 0, -1),
			stagingAct("update-prefix-error", "Update", "changes", 0, 2),
			stagingAct("commit-after-error", "Commit", "", 1, -1))
	case "accumulate-error-keeps-prefix":
		a = append(a, stagingAct("complete-accumulation", "AccumulateFrom", "complete", 0, -1),
			stagingAct("accumulate-prefix-error", "AccumulateFrom", "changes", 0, 2),
			stagingAct("bulk-after-error", "CommitBulk", "", 10, -1))
	case "update-initial-error-not-staged":
		a = append(a, stagingAct("update-empty-error", "Update", "changes", 0, 0),
			stagingAct("commit-empty-error-refused", "Commit", "", 1, -1),
			stagingAct("update-first-put-error", "Update", "changes", 0, 1),
			stagingAct("commit-first-put-error-refused", "Commit", "", 1, -1),
			stagingAct("complete-retry", "Update", "changes", 0, -1),
			stagingAct("commit-after-retry", "Commit", "", 1, -1))
	case "accumulate-initial-error-is-staged":
		a = append(a, stagingAct("accumulate-empty-error", "AccumulateFrom", "changes", 0, 0),
			stagingAct("commit-empty-error", "Commit", "", 1, -1),
			stagingAct("accumulate-first-put-error", "AccumulateFrom", "changes", 0, 1),
			stagingAct("commit-first-put-error", "Commit", "", 2, -1))
	case "update-replaces-accumulation":
		a = append(a, stagingAct("complete-accumulation", "AccumulateFrom", "complete", 0, -1),
			stagingAct("update-replaces-stage", "Update", "changes", 0, -1),
			stagingAct("bulk-after-replacement", "CommitBulk", "", 10, -1))
	case "clean-reopen-clears-staging":
		a = append(a, stagingAct("complete-stage", "Update", "complete", 0, -1),
			stagingAct("seed-commit", "Commit", "", 1, -1),
			stagingAct("accumulate-prefix-error", "AccumulateFrom", "changes", 0, 2),
			stagingAct("interrupted-stage-clean-reopen", "reopen", "", 0, -1),
			stagingAct("commit-after-reopen-refused", "Commit", "", 2, -1),
			stagingAct("full-patch-retry", "AccumulateFrom", "changes", 0, -1),
			stagingAct("commit-after-retry", "Commit", "", 2, -1))
	case "default-accumulation-control":
		a = append(a, stagingAct("complete-accumulation", "AccumulateFrom", "complete", 0, -1),
			stagingAct("changes-accumulation", "AccumulateFrom", "changes", 0, -1),
			stagingAct("bulk-after-default-replay", "CommitBulk", "", 10, -1))
	default:
		panic("unselected staging-boundary fixture")
	}
	return a
}

func stagingMust(err error) {
	if err != nil {
		panic(err)
	}
}
func stagingIdentifier(name string, height uint64) types.HashHeight {
	if height == 0 {
		return types.ZeroHashHeight
	}
	return types.HashHeight{Height: height, Hash: types.NewHash([]byte(fmt.Sprintf("synthetic-staging-boundary-v1/%s/A/%d", name, height)))}
}
func stagingIDRecord(value types.HashHeight) any {
	return map[string]any{"height": value.Height, "hash": value.Hash.String()}
}
func stagingKey(index int) []byte {
	address := bytes.Repeat([]byte{0x11}, 20)
	binary.BigEndian.PutUint32(address[16:], uint32(index))
	return append(append(append([]byte{3}, address...), 3), bytes.Repeat([]byte{0x22}, 10)...)
}
func stagingValue(amount uint64) []byte {
	value := make([]byte, 32)
	binary.BigEndian.PutUint64(value[24:], amount)
	return value
}
func stagingCompleteMap() map[int][]byte {
	state := map[int][]byte{}
	for i := 0; i < 8; i++ {
		amount := uint64(i + 1)
		if i == 0 {
			amount = 0
		}
		state[i] = stagingValue(amount)
	}
	return state
}

type stagingEntry struct {
	index int
	value []byte
}

func stagingEntries(name string) []stagingEntry {
	switch name {
	case "complete":
		entries := []stagingEntry{}
		for i := 0; i < 8; i++ {
			entries = append(entries, stagingEntry{i, stagingCompleteMap()[i]})
		}
		return entries
	case "changes":
		return []stagingEntry{{1, stagingValue(91)}, {2, nil}, {8, stagingValue(9)}}
	default:
		panic("unselected staging patch")
	}
}
func stagingTraceEntry(operation string, key, value []byte) any {
	return map[string]any{"operation": operation, "key": hex.EncodeToString(key), "value": stagingNullableBytes(value)}
}

type stagingRecorder struct {
	target db.PatchReplayer
	events *[]any
}

func (r *stagingRecorder) Put(key, value []byte) {
	*r.events = append(*r.events, stagingTraceEntry("Put", key, value))
	r.target.Put(key, value)
}
func (r *stagingRecorder) Delete(key []byte) {
	*r.events = append(*r.events, stagingTraceEntry("Delete", key, nil))
	r.target.Delete(key)
}

// Only this research wrapper injects an error. The unchanged default Batch.Replay
// returns nil; no default-patch corruption, storage failure or production exploit
// is inferred from this custom implementation of the public db.Patch interface.
type stagingResearchPatch struct {
	db.Patch
	entries    []stagingEntry
	faultAfter int
	events     *[]any
}

func (p *stagingResearchPatch) Replay(target db.PatchReplayer) error {
	recorder := &stagingRecorder{target: target, events: p.events}
	if p.faultAfter < 0 {
		return p.Patch.Replay(recorder)
	}
	require(p.faultAfter <= len(p.entries), "unselected staging replay cut")
	for _, entry := range p.entries[:p.faultAfter] {
		if entry.value == nil {
			recorder.Delete(stagingKey(entry.index))
		} else {
			recorder.Put(stagingKey(entry.index), entry.value)
		}
	}
	return errors.New("synthetic Patch.Replay failure")
}
func stagingPatch(name string, faultAfter int, events *[]any) db.Patch {
	patch, entries := db.NewPatch(), stagingEntries(name)
	for _, entry := range entries {
		if entry.value == nil {
			patch.Delete(stagingKey(entry.index))
		} else {
			patch.Put(stagingKey(entry.index), entry.value)
		}
	}
	return &stagingResearchPatch{patch, entries, faultAfter, events}
}

// The intended complete state is selected from fixture operations, before reads.
func stagingSelected(name string) map[int][]byte {
	state := stagingCompleteMap()
	if name == "update-initial-error-not-staged" || name == "accumulate-initial-error-is-staged" {
		state = map[int][]byte{}
	}
	state[1] = stagingValue(91)
	delete(state, 2)
	state[8] = stagingValue(9)
	return state
}

func stagingSelectedRoot(state map[int][]byte) (types.Hash, any) {
	indices := []int{}
	for index := range state {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	paths, values := []trie.Path{}, [][]byte{}
	digest := sha256.New()
	width := make([]byte, 8)
	for _, index := range indices {
		key, value := stagingKey(index), state[index]
		paths, values = append(paths, trie.Path(types.NewHash(key))), append(values, value)
		binary.BigEndian.PutUint64(width, uint64(len(key)))
		digest.Write(width)
		digest.Write(key)
		binary.BigEndian.PutUint64(width, uint64(len(value)))
		digest.Write(width)
		digest.Write(value)
	}
	root, err := trie.RootOfLeaves(paths, values)
	stagingMust(err)
	return root, map[string]any{"present_keys": len(state), "raw_map_sha256": hex.EncodeToString(digest.Sum(nil))}
}
func stagingStorage(ldb *leveldb.DB) any {
	counts := map[string]int{"frontier": 0, "node": 0, "refcount": 0, "version": 0, "format": 0}
	families := map[byte]string{0: "frontier", 1: "node", 2: "refcount", 3: "version", 5: "format"}
	digest := sha256.New()
	records, keyBytes, valueBytes := 0, 0, 0
	heights := []uint64{}
	width := make([]byte, 8)
	iter := ldb.NewIterator(nil, nil)
	for iter.Next() {
		k, v := iter.Key(), iter.Value()
		require(len(k) > 0, "empty staging-boundary store key")
		family, ok := families[k[0]]
		require(ok, "unknown staging-boundary store family")
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
			require(len(k) == 9, "wrong staging version key")
			heights = append(heights, binary.BigEndian.Uint64(k[1:]))
		}
	}
	iter.Release()
	stagingMust(iter.Error())
	return map[string]any{"records": records, "key_bytes": keyBytes, "value_bytes": valueBytes, "family_counts": counts, "retained_heights": heights, "records_sha256": hex.EncodeToString(digest.Sum(nil))}
}
func stagingNullableBytes(value []byte) any {
	if value == nil {
		return nil
	}
	return hex.EncodeToString(value)
}
func stagingNullableError(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}
func stagingObserve(name string, action stagingAction, err error, events any, tree *trie.NodeTree, ldb *leveldb.DB) any {
	rows := []any{}
	for _, height := range []uint64{0, 1, 2, 10} {
		for _, index := range []int{-1, 0, 1, 2, 8} {
			row := map[string]any{"identifier": stagingIDRecord(stagingIdentifier(name, height)), "key": nil, "root": nil, "value": nil, "proof": nil, "error": nil}
			if index == -1 {
				root, failure := tree.Root(stagingIdentifier(name, height))
				row["root"], row["error"] = root.String(), stagingNullableError(failure)
			} else {
				key := stagingKey(index)
				value, proof, failure := tree.Prove(stagingIdentifier(name, height), key)
				row["key"], row["value"], row["proof"], row["error"] = hex.EncodeToString(key), stagingNullableBytes(value), stagingNullableBytes(proof), stagingNullableError(failure)
			}
			rows = append(rows, row)
		}
	}
	var patch, height, faultAfter any
	if action.patch != "" {
		patch = action.patch
		if action.faultAfter >= 0 {
			faultAfter = action.faultAfter
		}
	}
	if action.operation == "Commit" || action.operation == "CommitBulk" {
		height = action.height
	}
	return map[string]any{"label": action.label, "operation": action.operation, "patch": patch, "target_height": height, "fault_after_callbacks": faultAfter, "replay_callbacks": events, "operation_error": stagingNullableError(err), "frontier": stagingIDRecord(tree.FrontierIdentifier()), "storage": stagingStorage(ldb), "reads": rows}
}
func stagingOpen(dir string) (*leveldb.DB, *trie.NodeTree) {
	ldb, err := leveldb.OpenFile(dir, nil)
	stagingMust(err)
	tree, err := trie.NewNodeTree(ldb)
	if err != nil {
		ldb.Close()
		panic(err)
	}
	return ldb, tree
}
func stagingCase(name, dir string) any {
	ldb, tree := stagingOpen(dir)
	defer func() { stagingMust(ldb.Close()) }()
	steps := []any{}
	for _, action := range stagingActions(name) {
		var err error
		var events any
		switch action.operation {
		case "observe":
		case "Update":
			trace := []any{}
			err = tree.Update(stagingPatch(action.patch, action.faultAfter, &trace))
			events = trace
		case "AccumulateFrom":
			trace := []any{}
			err = tree.AccumulateFrom(stagingPatch(action.patch, action.faultAfter, &trace))
			events = trace
		case "reopen":
			stagingMust(ldb.Close())
			ldb, tree = stagingOpen(dir)
		case "Commit":
			err = tree.Commit(stagingIdentifier(name, action.height))
		case "CommitBulk":
			err = tree.CommitBulk(stagingIdentifier(name, action.height))
		default:
			panic("unselected staging operation")
		}
		steps = append(steps, stagingObserve(name, action, err, events, tree, ldb))
	}
	stagingMust(ldb.Close())
	ldb, tree = stagingOpen(dir)
	steps = append(steps, stagingObserve(name, stagingAct("clean-reopen", "reopen", "", 0, -1), nil, nil, tree, ldb))
	stagingMust(ldb.CompactRange(util.Range{}))
	stagingMust(ldb.Close())
	ldb, tree = stagingOpen(dir)
	steps = append(steps, stagingObserve(name, stagingAct("compacted-clean-reopen", "compact-reopen", "", 0, -1), nil, nil, tree, ldb))
	selectedRoot, manifest := stagingSelectedRoot(stagingSelected(name))
	identifier := tree.FrontierIdentifier()
	observedRoot, err := tree.Root(identifier)
	stagingMust(err)
	checks := []any{}
	for _, index := range []int{0, 1, 2, 8} {
		key := stagingKey(index)
		value, proof, err := tree.Prove(identifier, key)
		stagingMust(err)
		p := proofCase{Path: types.NewHash(key).String(), Value: hex.EncodeToString(value), Proof: hex.EncodeToString(proof), Present: value != nil, Root: observedRoot.String()}
		own := nodeResult(p)
		p.Root = selectedRoot.String()
		checks = append(checks, map[string]any{"key": hex.EncodeToString(key), "value": stagingNullableBytes(value), "proof": hex.EncodeToString(proof), "own_root_result": own, "selected_fixture_result": nodeResult(p)})
	}
	return map[string]any{"name": name, "steps": steps, "boundary": map[string]any{"identifier": stagingIDRecord(identifier), "selected_fixture_root": selectedRoot.String(), "selected_fixture_manifest": manifest, "observed_root": observedRoot.String(), "root_matches_selected_fixture": observedRoot == selectedRoot, "production_replay_failure_qualified": false, "consumer_result": "REFUSED", "proof_checks": checks}}
}
func generateStagingBoundary() any {
	cases := []any{}
	for _, name := range []string{"update-error-keeps-prior-stage", "accumulate-error-keeps-prefix", "update-initial-error-not-staged", "accumulate-initial-error-is-staged", "update-replaces-accumulation", "clean-reopen-clears-staging", "default-accumulation-control"} {
		func() {
			temporary, err := os.MkdirTemp("", "candidate-staging-boundary-")
			stagingMust(err)
			defer func() { stagingMust(os.RemoveAll(temporary)) }()
			cases = append(cases, stagingCase(name, filepath.Join(temporary, "owned-tree")))
		}()
	}
	return map[string]any{"format_version": 1, "kind": "candidate-staging-boundary-research", "backend": "NodeTree", "source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"scope": map[string]bool{"synthetic": true, "unsigned": true, "actual_NodeTree_disk_APIs_executed": true, "actual_NodeTree_CommitBulk_executed": true, "actual_NodeTree_AccumulateFrom_executed": true, "custom_Patch_Replay_errors_injected": true, "default_Batch_Replay_executed": true, "default_Batch_Replay_failure_observed": false, "production_replay_failure_qualified": false, "single_serial_caller_for_staged_sequence": true, "small_owned_temporary_disk_LevelDB": true, "controlled_clean_reopen_executed": true, "manual_compaction_executed": true, "logical_storage_records_measured": true, "owned_databases_removed": true, "selected_fixture_not_authenticated_snapshot": true, "resource_measurements_executed": false, "chain_component_Init_executed": false, "chain_Start_executed": false, "background_build_executed": false, "full_node_started": false, "node_tests_executed": false, "network_execution": false, "RPC_executed": false, "signing": false, "transactions": false, "power_loss_qualified": false, "production_crash_recovery_qualified": false, "authenticated_retained_version_provenance_qualified": false, "realistic_retention_resource_budgets_qualified": false, "profile_agreed": false, "network_activation_authenticated": false, "runtime_state_proof_acceptance": false}, "cases": cases}
}
func init() { stagingBoundaryGenerator = generateStagingBoundary }
