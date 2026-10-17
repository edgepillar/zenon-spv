//go:build candidate_offline_rebuild_successor

// SPDX-License-Identifier: GPL-3.0-only
// Observe exported offline helpers with controlled unsigned chain adapters.
package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/inconshreveable/log15"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
)

const rebuildInputSHA = "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75"

type rebuildSelection struct {
	FormatVersion      uint64   `json:"format_version"`
	Kind               string   `json:"kind"`
	NodeRevision       string   `json:"node_revision"`
	NodeTree           string   `json:"node_tree"`
	TerminalParentTree string   `json:"terminal_parent_tree"`
	CallerPatchSHA256  string   `json:"caller_patch_sha256"`
	HistoryHeight      uint64   `json:"history_height"`
	MutationKeys       []string `json:"mutation_keys"`
	SelectedProofs     []struct {
		Selection string `json:"selection"`
		RawKey    string `json:"raw_key"`
	} `json:"selected_proofs"`
	QueryHeights []uint64 `json:"query_heights"`
}

type rebuildApply struct {
	data db.DB
	err  error
}

func (a *rebuildApply) Put(k, v []byte) {
	if a.err == nil {
		a.err = a.data.Put(k, v)
	}
}
func (a *rebuildApply) Delete(k []byte) {
	if a.err == nil {
		a.err = a.data.Delete(k)
	}
}

type rebuildGenesis struct{ recoveryGenesis }

func (*rebuildGenesis) GetGenesisMomentum() *nom.Momentum { return recoveryMomentum("G", 1) }
func (*rebuildGenesis) ChainIdentifier() uint64           { return 1 }

type rebuildFaultDB struct {
	db.DB
	key, value []byte
	fault      string
}

func (d *rebuildFaultDB) Get(key []byte) ([]byte, error) {
	if bytes.Equal(key, d.key) {
		if d.fault == "missing-momentum" {
			return nil, leveldb.ErrNotFound
		}
		if d.fault == "read-error" {
			return nil, errors.New("synthetic offline rebuild store read failure")
		}
		return append([]byte(nil), d.value...), nil
	}
	return d.DB.Get(key)
}

type rebuildManager struct {
	*recoveryManager
	frontierCalls, faultsApplied int
	enumerationFault             string
	patchCalls                   map[uint64]int
}

func (m *rebuildManager) Frontier() db.DB {
	m.frontierCalls++
	data := m.recoveryManager.Frontier()
	if m.enumerationFault == "" || m.frontierCalls != 3 {
		return data
	}
	m.faultsApplied++
	if m.enumerationFault == "stopped-store" {
		return nil
	}
	id := recoveryIdentifier("G", 60)
	momentum := recoveryMomentum("G", 61)
	if m.enumerationFault == "wrong-hash" {
		momentum = recoveryMomentum("X", 60)
	}
	raw, err := momentum.Serialize()
	recoveryMust(err)
	return &rebuildFaultDB{DB: data, key: db.FrontierWriteKeys(id)[2], value: raw, fault: m.enumerationFault}
}
func (m *rebuildManager) GetPatch(id types.HashHeight) db.Patch {
	if id != recoveryIdentifier("G", id.Height) || id.Height < 1 || id.Height > 64 {
		panic("unselected offline rebuild patch")
	}
	m.patchCalls[id.Height]++
	return m.recoveryManager.GetPatch(id)
}
func rebuildError(err error) any {
	if err != nil {
		if strings.HasPrefix(err.Error(), "state tree rebuild: missing or mismatched momentum at height ") {
			return "invalid-chain-momentum"
		}
		if err.Error() == "synthetic offline rebuild store read failure" {
			return "injected-chain-read"
		}
		if err.Error() == "can't rebuild state tree: chain db is stopped" {
			return "chain-store-stopped"
		}
	}
	return recoveryError(err)
}
func rebuildRead(path string, limit int64) []byte {
	f, err := os.Open(path)
	recoveryMust(err)
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	recoveryMust(err)
	if int64(len(raw)) > limit {
		panic("selected offline rebuild input exceeded bound")
	}
	return raw
}
func rebuildInputs() (db.Patch, rebuildSelection, [][]byte, string) {
	raw := rebuildRead(os.Getenv("ZENON_OFFLINE_REBUILD_INPUT"), 16<<20)
	if len(raw) != 10849399 || fmt.Sprintf("%x", sha256.Sum256(raw)) != rebuildInputSHA {
		panic("selected source genesis identity mismatch")
	}
	initial, err := db.NewPatchFromDump(raw)
	recoveryMust(err)
	encoded := rebuildRead(os.Getenv("ZENON_OFFLINE_REBUILD_SELECTION"), 256<<10)
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	if digest != os.Getenv("ZENON_OFFLINE_REBUILD_SELECTION_SHA256") {
		panic("independent selection identity mismatch")
	}
	var selected rebuildSelection
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	recoveryMust(decoder.Decode(&selected))
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		panic("trailing selection data")
	}
	if selected.FormatVersion != 1 || selected.Kind != "successor-offline-rebuild-component-selection" || selected.HistoryHeight != 64 ||
		selected.NodeRevision != "9c71ae82fc983e16f914ae085d4034030c8ebe3b" || selected.NodeTree != "d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6" ||
		selected.TerminalParentTree != "2ab95e67aa184e7faa3f080c6b08d8980a8e16f9" ||
		selected.CallerPatchSHA256 != "674baa97de325e69517d730f2fc638399db4411e69b079f6a4bbe2365ffe39fb" ||
		len(selected.MutationKeys) != 256 || len(selected.SelectedProofs) != 15 {
		panic("unselected offline rebuild contract")
	}
	heights, err := json.Marshal(selected.QueryHeights)
	recoveryMust(err)
	if string(heights) != "[1,54,58,59,60,64]" {
		panic("unselected proof horizons")
	}
	keys, seen := [][]byte{}, map[string]bool{}
	for _, text := range selected.MutationKeys {
		key, err := hex.DecodeString(text)
		recoveryMust(err)
		if len(key) != 32 || key[0] != 3 || key[21] != 3 || seen[text] {
			panic("invalid selected balance key")
		}
		seen[text] = true
		keys = append(keys, key)
	}
	seen = map[string]bool{}
	for _, sample := range selected.SelectedProofs {
		key, err := hex.DecodeString(sample.RawKey)
		recoveryMust(err)
		if len(key) < 1 || len(key) > 128 || sample.Selection == "" || seen[sample.RawKey] {
			panic("invalid selected proof key")
		}
		seen[sample.RawKey] = true
	}
	return initial, selected, keys, digest
}
func rebuildMutation(height uint64, keys [][]byte) db.Patch {
	p := db.NewPatch()
	key := keys[(height-2)%uint64(len(keys))]
	if height%11 == 0 {
		p.Delete(key)
	} else {
		value := make([]byte, 32)
		if height%7 != 0 {
			binary.BigEndian.PutUint64(value[24:], 1000000+height)
		}
		p.Put(key, value)
	}
	return p
}
func rebuildChain(initial db.Patch, keys [][]byte, height uint64) (*chain, *rebuildManager) {
	base, cache := &recoveryManager{}, &recoveryCache{}
	recoverySelect(base, cache, "G", height)
	for h := uint64(1); h <= height; h++ {
		patch := initial
		if h > 1 {
			patch = rebuildMutation(h, keys)
		}
		base.patches[recoveryIdentifier("G", h)] = patch
		applied := &rebuildApply{data: base.data}
		recoveryMust(patch.Replay(applied))
		recoveryMust(applied.err)
		momentum := recoveryMomentum("G", h)
		encoded, err := momentum.Serialize()
		recoveryMust(err)
		recoveryMust(db.SetFrontier(base.data, momentum.Identifier(), encoded))
	}
	manager := &rebuildManager{recoveryManager: base, patchCalls: map[uint64]int{}}
	c := NewChain(manager, cache, &rebuildGenesis{}, "", false)
	manager.frontierCalls = 0
	return c, manager
}
func rebuildDiskDigest(ldb *leveldb.DB) any {
	digest := sha256.New()
	count, size := 0, 0
	it := ldb.NewIterator(nil, nil)
	for it.Next() {
		key, value := it.Key(), it.Value()
		count++
		size += len(key) + len(value)
		_, _ = digest.Write(common.Uint64ToBytes(uint64(len(key))))
		_, _ = digest.Write(key)
		_, _ = digest.Write(common.Uint64ToBytes(uint64(len(value))))
		_, _ = digest.Write(value)
	}
	err := it.Error()
	it.Release()
	recoveryMust(err)
	return map[string]any{"records": count, "logical_bytes": size, "sha256": fmt.Sprintf("%x", digest.Sum(nil))}
}
func rebuildSnapshot(dir string, selection rebuildSelection) any {
	ldb, err := leveldb.OpenFile(dir, nil)
	recoveryMust(err)
	defer func() { recoveryMust(ldb.Close()) }()
	tree, err := trie.NewNodeTree(ldb)
	recoveryMust(err)
	frontier := tree.FrontierIdentifier()
	roots, queries := []any{}, []any{}
	for h := uint64(1); h <= frontier.Height; h++ {
		id := recoveryIdentifier("G", h)
		root, err := tree.Root(id)
		roots = append(roots, map[string]any{"identifier": recoveryID(id), "root": root.String(), "error": rebuildError(err)})
	}
	for _, h := range selection.QueryHeights {
		if h > frontier.Height {
			continue
		}
		id := recoveryIdentifier("G", h)
		root, rootErr := tree.Root(id)
		proofs := []any{}
		for _, sample := range selection.SelectedProofs {
			key, err := hex.DecodeString(sample.RawKey)
			recoveryMust(err)
			value, proof, err := tree.Prove(id, key)
			proofs = append(proofs, map[string]any{"selection": sample.Selection, "raw_key": sample.RawKey, "value": recoveryBytes(value), "proof": recoveryBytes(proof), "error": rebuildError(err), "consumer_result": "REFUSED"})
		}
		queries = append(queries, map[string]any{"identifier": recoveryID(id), "root": root.String(), "root_error": rebuildError(rootErr), "proofs": proofs})
	}
	refusals := []any{}
	for _, item := range []struct {
		name string
		id   types.HashHeight
	}{
		{"wrong-hash", recoveryIdentifier("X", frontier.Height)},
		{"height-only", types.HashHeight{Height: frontier.Height}},
		{"missing-version", recoveryIdentifier("G", frontier.Height+1)},
	} {
		root, err := tree.Root(item.id)
		refusals = append(refusals, map[string]any{"name": item.name, "identifier": recoveryID(item.id), "root": root.String(), "error": rebuildError(err)})
	}
	return map[string]any{"frontier": recoveryID(frontier), "roots": roots, "queries": queries, "identity_refusals": refusals, "logical_records": rebuildDiskDigest(ldb)}
}
func rebuildFresh(parent, name string) string {
	dir := filepath.Join(parent, "node", name)
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		panic("existing offline rebuild database refused")
	}
	return dir
}
func rebuildSnapshotDigest(value any) any {
	raw, err := json.Marshal(value)
	recoveryMust(err)
	return map[string]any{"complete_snapshot_sha256": fmt.Sprintf("%x", sha256.Sum256(append(raw, '\n')))}
}
func rebuildClosedReopens(dir string, selection rebuildSelection) []any {
	first, second := rebuildSnapshot(dir, selection), rebuildSnapshot(dir, selection)
	return []any{first, rebuildSnapshotDigest(second)}
}
func rebuildResult(value *RebuiltStateTree) any {
	if value == nil {
		return nil
	}
	roots := map[uint64]string{}
	for height, root := range value.Roots {
		roots[height] = root.String()
	}
	return map[string]any{"frontier": recoveryID(value.Frontier), "roots": roots}
}
func rebuildCall(initial db.Patch, keys [][]byte, selection rebuildSelection, parent, name string, archive bool, retention uint64) any {
	c, manager := rebuildChain(initial, keys, 64)
	dir := rebuildFresh(parent, name)
	rebuilt, err := RebuildStateTree(c, dir, archive, retention)
	return map[string]any{"name": name, "operation": "RebuildStateTree", "archive": archive, "retention_override": retention, "result": rebuildResult(rebuilt), "error": rebuildError(err), "frontier_snapshots": manager.frontierCalls, "patch_requests": manager.patchCalls, "closed_reopens": rebuildClosedReopens(dir, selection)}
}
func rebuildPrebuild(initial db.Patch, keys [][]byte, selection rebuildSelection, parent string, delta bool) any {
	name, height := "prebuild-reopen", uint64(64)
	if delta {
		name, height = "prebuild-delta", 32
	}
	c, manager := rebuildChain(initial, keys, height)
	dir := rebuildFresh(parent, name)
	frontier, err := PrebuildStateTree(c, dir, false)
	recoveryMust(err)
	before := rebuildSnapshot(dir, selection)
	initialCalls := manager.patchCalls
	if delta {
		c, manager = rebuildChain(initial, keys, 64)
	} else {
		manager.patchCalls = map[uint64]int{}
	}
	build, err := NewStateTreeBuild(c, dir, 0, 0)
	recoveryMust(err)
	steps := []any{}
	for count := 0; ; count++ {
		if count >= 64 {
			panic("offline delta exceeded selected bounded step count")
		}
		done, err := build.Step()
		steps = append(steps, map[string]any{"done": done, "error": rebuildError(err), "frontier": recoveryID(build.Frontier()), "ready": build.Ready()})
		if err != nil || done {
			break
		}
	}
	root, rootErr := build.Root(recoveryIdentifier("G", 64))
	ready := build.Ready()
	recoveryMust(build.Stop())
	return map[string]any{"name": name, "operation": "PrebuildStateTree+StateTreeBuild", "prebuild_frontier": recoveryID(frontier), "prebuild_snapshot": before, "initial_patch_requests": initialCalls, "delta_patch_requests": manager.patchCalls, "steps": steps, "ready_before_stop": ready, "final_root": root.String(), "final_root_error": rebuildError(rootErr), "closed_reopens": rebuildClosedReopens(dir, selection)}
}
func rebuildFault(initial db.Patch, keys [][]byte, selection rebuildSelection, parent, fault string) any {
	c, manager := rebuildChain(initial, keys, 64)
	dir := rebuildFresh(parent, "fault-"+fault)
	_, err := PrebuildStateTree(c, dir, false)
	recoveryMust(err)
	if fault == "missing-retained-hash" || fault == "wrong-retained-hash" {
		ldb, err := leveldb.OpenFile(dir, nil)
		recoveryMust(err)
		key := recoveryVersionKey(6, 32)
		if fault == "missing-retained-hash" {
			recoveryMust(ldb.Delete(key, nil))
		} else {
			id := recoveryIdentifier("X", 32)
			recoveryMust(ldb.Put(key, id.Hash[:], nil))
		}
		recoveryMust(ldb.Close())
	} else {
		manager.enumerationFault = fault
	}
	before := rebuildSnapshotDigest(rebuildSnapshot(dir, selection))
	manager.frontierCalls = 0
	rebuilt, err := RebuildStateTree(c, dir, false, 0)
	return map[string]any{"name": "fault-" + fault, "operation": "RebuildStateTree-refusal", "fault": fault, "result": rebuildResult(rebuilt), "error": rebuildError(err), "frontier_snapshots": manager.frontierCalls, "fault_snapshots_applied": manager.faultsApplied, "before": before, "closed_reopens": rebuildClosedReopens(dir, selection)}
}
func TestCandidateOfflineRebuildSuccessor(t *testing.T) {
	variant, parent := os.Getenv("ZENON_OFFLINE_REBUILD_VARIANT"), os.Getenv("ZENON_OFFLINE_REBUILD_WORKSPACE")
	if (variant != "terminal-parent" && variant != "full-identifier") || parent == "" {
		t.Fatal("select one prepared variant and a new owned workspace")
	}
	if _, err := os.Lstat(filepath.Join(parent, "node")); !os.IsNotExist(err) {
		t.Fatal("existing case data refused")
	}
	initial, selection, keys, selectionSHA := rebuildInputs()
	handler := common.ChainLogger.GetHandler()
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	defer common.ChainLogger.SetHandler(handler)
	rows := []any{
		rebuildCall(initial, keys, selection, parent, "rebuild-default", false, 0),
		rebuildCall(initial, keys, selection, parent, "rebuild-short-pruned", false, 5),
		rebuildCall(initial, keys, selection, parent, "rebuild-short-archive", true, 5),
		rebuildPrebuild(initial, keys, selection, parent, false),
		rebuildPrebuild(initial, keys, selection, parent, true),
	}
	if variant == "full-identifier" {
		for _, fault := range []string{"wrong-height", "missing-momentum", "wrong-hash", "stopped-store", "read-error", "missing-retained-hash", "wrong-retained-hash"} {
			rows = append(rows, rebuildFault(initial, keys, selection, parent, fault))
		}
	}
	runtimeTree := "2ab95e67aa184e7faa3f080c6b08d8980a8e16f9"
	if variant == "full-identifier" {
		runtimeTree = "e60c875a06361f04d05301c0e4c61fd429995c5a"
	}
	observation := map[string]any{"kind": "successor-offline-rebuild-component-observation", "format_version": 1, "variant": variant, "node_revision": selection.NodeRevision, "node_tree": selection.NodeTree, "runtime_tree": runtimeTree, "Go_version": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH, "raw_input_sha256": rebuildInputSHA, "selection_sha256": selectionSHA, "history_height": 64, "cases": rows, "actual_exported_offline_helpers_executed": true, "manager_and_genesis_are_controlled_adapters": true, "source_identifiers_and_suffix_patches_are_synthetic": true, "full_node_started": false, "chain_Init_or_Start_executed": false, "network_executed": false, "signing_or_broadcast_executed": false, "accepted_header_root_binding": false, "profile_agreed": false, "production_resources_qualified": false, "consumer_result": "REFUSED"}
	raw, err := json.Marshal(observation)
	recoveryMust(err)
	if len(raw) > 4<<20 {
		t.Fatal("bounded offline observation exceeded output cap")
	}
	fmt.Printf("SUCCESSOR_OFFLINE_REBUILD_OBSERVATION=%s\n", raw)
}
