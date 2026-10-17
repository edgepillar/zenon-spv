//go:build candidate_default_retention_successor

// SPDX-License-Identifier: GPL-3.0-only
// Real StateTree lifecycle with source defaults and a controlled unsigned history.
package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/zenon-network/go-zenon/chain/cache/storage"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

const defaultRetentionHeight = uint64(32768)
const defaultRetentionWindow = uint64(17380)

type defaultRetentionSelection struct {
	NodeRevision             string `json:"node_revision"`
	NodeTree                 string `json:"node_tree"`
	RuntimeTree              string `json:"runtime_tree"`
	FormatVersion            uint64 `json:"format_version"`
	Kind                     string `json:"kind"`
	HistoryHeight            uint64 `json:"history_height"`
	RetentionOverride        uint64 `json:"retention_override"`
	BulkBatchOverride        uint64 `json:"bulk_batch_override"`
	SourceEffectiveRetention uint64 `json:"source_effective_retention"`
	RawInput                 struct {
		SHA256 string `json:"sha256"`
		Bytes  uint64 `json:"bytes"`
	} `json:"raw_input"`
	MutationKeys   []string             `json:"mutation_keys"`
	SelectedProofs []genesisBuildSample `json:"selected_proofs"`
	QueryHeights   []uint64             `json:"query_heights"`
}

type defaultRetentionManager struct {
	*recoveryManager
	calls map[uint64]int
	last  uint64
	frame hash.Hash
}

type defaultRetentionOperation struct {
	count int
	key   []byte
	value []byte
	put   bool
}

func (p *defaultRetentionOperation) Put(key, value []byte) {
	p.count++
	p.key, p.value, p.put = append([]byte(nil), key...), append([]byte(nil), value...), true
}
func (p *defaultRetentionOperation) Delete(key []byte) {
	p.count++
	p.key, p.value, p.put = append([]byte(nil), key...), nil, false
}
func (m *defaultRetentionManager) GetPatch(id types.HashHeight) db.Patch {
	if id != recoveryIdentifier("G", id.Height) || id.Height != m.last+1 || id.Height > defaultRetentionHeight {
		panic("unselected or repeated default-retention patch request")
	}
	m.last = id.Height
	m.calls[id.Height]++
	patch := m.recoveryManager.GetPatch(id)
	if id.Height > 1 {
		operation := &defaultRetentionOperation{}
		recoveryMust(patch.Replay(operation))
		if operation.count != 1 || len(operation.key) != 32 || operation.key[0] != 3 || operation.key[21] != 3 ||
			(operation.put && len(operation.value) != 32) {
			panic("unexpected default-retention patch shape")
		}
		var height [8]byte
		binary.BigEndian.PutUint64(height[:], id.Height)
		_, _ = m.frame.Write(height[:])
		_, _ = m.frame.Write(operation.key)
		if operation.put {
			_, _ = m.frame.Write([]byte{1})
			_, _ = m.frame.Write(operation.value)
		} else {
			_, _ = m.frame.Write([]byte{0})
		}
	}
	return patch
}

func defaultRetentionInputs() (db.Patch, defaultRetentionSelection, [][]byte, string) {
	raw := genesisBuildRead(os.Getenv("ZENON_DEFAULT_RETENTION_INPUT"), 32<<20)
	if len(raw) != 10849399 || fmt.Sprintf("%x", sha256.Sum256(raw)) != genesisBuildInputSHA {
		panic("source genesis input identity mismatch")
	}
	initial, err := db.NewPatchFromDump(raw)
	recoveryMust(err)
	selected := genesisBuildRead(os.Getenv("ZENON_DEFAULT_RETENTION_SELECTION"), 1<<20)
	digest := fmt.Sprintf("%x", sha256.Sum256(selected))
	if digest != os.Getenv("ZENON_DEFAULT_RETENTION_SELECTION_SHA256") {
		panic("independently selected workload identity mismatch")
	}
	var selection defaultRetentionSelection
	decoder := json.NewDecoder(bytes.NewReader(selected))
	decoder.DisallowUnknownFields()
	recoveryMust(decoder.Decode(&selection))
	if selection.FormatVersion != 1 || selection.Kind != "successor-source-default-retention-component-selection" ||
		selection.NodeRevision != "9c71ae82fc983e16f914ae085d4034030c8ebe3b" ||
		selection.NodeTree != "d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6" ||
		selection.RuntimeTree != "2ab95e67aa184e7faa3f080c6b08d8980a8e16f9" ||
		selection.HistoryHeight != defaultRetentionHeight || selection.SourceEffectiveRetention != defaultRetentionWindow ||
		selection.RetentionOverride != 0 || selection.BulkBatchOverride != 0 ||
		selection.RawInput.SHA256 != genesisBuildInputSHA || selection.RawInput.Bytes != 10849399 ||
		len(selection.MutationKeys) != 256 || len(selection.SelectedProofs) != 15 {
		panic("unselected default-retention workload")
	}
	expectedHeights := []uint64{1, 15387, 15388, 15389, 32758, 32768}
	a, err := json.Marshal(selection.QueryHeights)
	recoveryMust(err)
	b, err := json.Marshal(expectedHeights)
	recoveryMust(err)
	if !bytes.Equal(a, b) {
		panic("query horizon selection mismatch")
	}
	keys, seen := [][]byte{}, map[string]bool{}
	for _, text := range selection.MutationKeys {
		key, err := hex.DecodeString(text)
		recoveryMust(err)
		if len(key) != 32 || key[0] != 3 || key[21] != 3 || seen[text] {
			panic("invalid selected balance key")
		}
		seen[text] = true
		keys = append(keys, key)
	}
	seen = map[string]bool{}
	for _, sample := range selection.SelectedProofs {
		key, err := hex.DecodeString(sample.RawKey)
		recoveryMust(err)
		if len(key) == 0 || len(key) > 128 || len(sample.Selection) == 0 || len(sample.Selection) > 64 || seen[sample.RawKey] {
			panic("invalid selected proof query")
		}
		seen[sample.RawKey] = true
	}
	return initial, selection, keys, digest
}

func defaultRetentionPatch(height uint64, keys [][]byte) db.Patch {
	patch := db.NewPatch()
	key := keys[(height-2)%uint64(len(keys))]
	if height%11 == 0 {
		patch.Delete(key)
	} else {
		value := make([]byte, 32)
		if height%7 != 0 {
			binary.BigEndian.PutUint64(value[24:], 1000000+height)
		}
		patch.Put(key, value)
	}
	return patch
}

func defaultRetentionFixture(initial db.Patch, keys [][]byte) (*defaultRetentionManager, *recoveryCache, *genesisBuildGenesis) {
	manager, cache := &recoveryManager{}, &recoveryCache{}
	recoverySelect(manager, cache, "G", defaultRetentionHeight)
	for h := uint64(1); h <= defaultRetentionHeight; h++ {
		patch := initial
		if h > 1 {
			patch = defaultRetentionPatch(h, keys)
		}
		manager.patches[recoveryIdentifier("G", h)] = patch
		applied := &genesisBuildApply{db: manager.data}
		recoveryMust(patch.Replay(applied))
		recoveryMust(applied.err)
		if h == 1 {
			for _, key := range keys {
				value, err := manager.data.Get(key)
				recoveryMust(err)
				if len(value) != 32 {
					panic("selected mutation key is not a source balance")
				}
			}
		}
		momentum := recoveryMomentum("G", h)
		encoded, err := momentum.Serialize()
		recoveryMust(err)
		recoveryMust(db.SetFrontier(manager.data, momentum.Identifier(), encoded))
	}
	return &defaultRetentionManager{recoveryManager: manager, calls: map[uint64]int{}, frame: sha256.New()},
		cache, &genesisBuildGenesis{}
}

func defaultRetentionDefaults(t *testing.T, c *chain) {
	t.Helper()
	if c.stateTree.retentionOverride != 0 || c.stateTree.bulkBatchOverride != 0 ||
		c.stateTree.retention() != defaultRetentionWindow || retentionFloor() != defaultRetentionWindow ||
		c.stateTree.bulkBatchSize() != stateTreeBuildBulkBatchSize || stateTreeBuildBulkBatchSize != 10000 ||
		storage.GetRollbackCacheSize() != 100 {
		t.Fatal("source defaults were not preserved")
	}
}

func defaultRetentionWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(480 * time.Second):
		t.Fatal("default-retention worker did not finish within the selected deadline")
	}
}

func defaultRetentionQueries(c *chain, selection defaultRetentionSelection) []any {
	result := []any{}
	for _, height := range selection.QueryHeights {
		id := recoveryIdentifier("G", height)
		root, err := c.StateRoot(id)
		proofs := []any{}
		for _, sample := range selection.SelectedProofs {
			key, err := hex.DecodeString(sample.RawKey)
			recoveryMust(err)
			value, proof, err := c.GetProof(id, key)
			proofs = append(proofs, map[string]any{"selection": sample.Selection, "raw_key": sample.RawKey,
				"value": recoveryBytes(value), "proof": recoveryBytes(proof), "error": recoveryError(err), "consumer_result": "REFUSED"})
		}
		result = append(result, map[string]any{"height": height, "root": root.String(), "root_error": recoveryError(err), "proofs": proofs})
	}
	for _, id := range []types.HashHeight{recoveryIdentifier("X", defaultRetentionHeight), types.ZeroHashHeight} {
		root, err := c.StateRoot(id)
		result = append(result, map[string]any{"identifier": recoveryID(id), "root": root.String(), "root_error": recoveryError(err)})
	}
	return result
}

func TestCandidateDefaultRetentionSuccessor(t *testing.T) {
	policy := os.Getenv("ZENON_DEFAULT_RETENTION_POLICY")
	parent := os.Getenv("ZENON_DEFAULT_RETENTION_WORKSPACE")
	if (policy != "pruned" && policy != "archive") || parent == "" {
		t.Fatal("select one policy and a new owned case workspace")
	}
	dir := filepath.Join(parent, "node")
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("existing database refused")
	}
	initial, selection, keys, selectionSHA := defaultRetentionInputs()
	handler := common.ChainLogger.GetHandler()
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	defer common.ChainLogger.SetHandler(handler)
	oldSpork := types.SporkAddress
	defer func() { types.SporkAddress = oldSpork }()
	started := time.Now()
	manager, cache, genesis := defaultRetentionFixture(initial, keys)
	setupNS := time.Since(started).Nanoseconds()
	archive := policy == "archive"
	c := NewChain(manager, cache, genesis, dir, archive)
	stopped := false
	defer func() {
		if !stopped {
			_ = c.Stop()
		}
	}()
	defaultRetentionDefaults(t, c)
	started = time.Now()
	recoveryMust(c.Init())
	initNS := time.Since(started).Nanoseconds()
	if c.StateTreeReady() {
		t.Fatal("the initial large gap was unexpectedly ready")
	}
	initialRoot, initialErr := c.StateRoot(recoveryIdentifier("G", defaultRetentionHeight))
	started = time.Now()
	recoveryMust(c.Start())
	exited := c.stateTree.buildExited
	if exited == nil {
		t.Fatal("worker exit handle missing")
	}
	defaultRetentionWait(t, exited)
	workerNS := time.Since(started).Nanoseconds()
	if !c.StateTreeReady() || c.stateTree.tree.FrontierIdentifier() != recoveryIdentifier("G", defaultRetentionHeight) {
		t.Fatal("worker did not reach the exact selected frontier")
	}
	defaultRetentionDefaults(t, c)
	before := genesisBuildSnapshot(c.stateTree.ldb)
	queries := defaultRetentionQueries(c, selection)
	started = time.Now()
	recoveryMust(c.Stop())
	stopped = true
	stopNS := time.Since(started).Nanoseconds()
	publicRoot, publicErr := c.StateRoot(recoveryIdentifier("G", defaultRetentionHeight))
	rawRoot, rawErr := c.stateTree.tree.Root(recoveryIdentifier("G", defaultRetentionHeight))
	closed := genesisBuildClosedSnapshot(dir)
	started = time.Now()
	c = NewChain(manager, cache, genesis, dir, archive)
	stopped = false
	defaultRetentionDefaults(t, c)
	recoveryMust(c.Init())
	if !c.StateTreeReady() {
		t.Fatal("clean reopen did not recover readiness")
	}
	reopened := genesisBuildSnapshot(c.stateTree.ldb)
	reopenedQueries := defaultRetentionQueries(c, selection)
	recoveryMust(c.Stop())
	stopped = true
	reopenNS := time.Since(started).Nanoseconds()
	for h := uint64(1); h <= defaultRetentionHeight; h++ {
		if manager.calls[h] != 1 {
			t.Fatalf("patch %d was not requested exactly once", h)
		}
	}
	if len(manager.calls) != int(defaultRetentionHeight) || manager.last != defaultRetentionHeight {
		t.Fatal("incomplete actual patch inventory")
	}
	same := func(left, right any) bool {
		a, err := json.Marshal(left)
		recoveryMust(err)
		b, err := json.Marshal(right)
		recoveryMust(err)
		return bytes.Equal(a, b)
	}
	if !same(before, closed) || !same(before, reopened) || !same(queries, reopenedQueries) {
		t.Fatal("logical data or proof queries changed across clean stop/reopen")
	}
	tables, err := json.Marshal(map[string]any{"snapshot": before, "queries": queries})
	recoveryMust(err)
	tables = append(tables, '\n')
	if len(tables) > 64<<20 {
		t.Fatal("logical tables exceeded the selected output bound")
	}
	observation := map[string]any{
		"kind": "successor-source-default-retention-component-observation", "policy": policy,
		"node_revision": selection.NodeRevision, "node_tree": selection.NodeTree, "runtime_tree": selection.RuntimeTree,
		"Go_version": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH,
		"history_height": defaultRetentionHeight, "selection_sha256": selectionSHA, "raw_input_sha256": genesisBuildInputSHA,
		"retention_override": c.stateTree.retentionOverride, "bulk_batch_override": c.stateTree.bulkBatchOverride,
		"effective_retention": c.stateTree.retention(), "rollback_cache": storage.GetRollbackCacheSize(),
		"retention_margin": stateTreeRetentionMargin, "bulk_batch_cap": c.stateTree.bulkBatchSize(),
		"tail_batch_cap": stateTreeBuildTailBatchSize, "batch_budget_ns": int64(stateTreeBuildBatchBudget),
		"fixture_initialization_ns": setupNS, "component_init_ns": initNS, "background_worker_elapsed_ns": workerNS,
		"stop_elapsed_ns": stopNS, "clean_reopen_elapsed_ns": reopenNS,
		"initial_root": initialRoot.String(), "initial_root_error": recoveryError(initialErr),
		"post_stop_public_root": publicRoot.String(), "post_stop_public_error": recoveryError(publicErr),
		"post_stop_direct_root": rawRoot.String(), "post_stop_direct_error": recoveryError(rawErr),
		"patch_heights_requested": len(manager.calls), "each_patch_requested_once": true,
		"actual_patch_frame_sha256":  fmt.Sprintf("%x", manager.frame.Sum(nil)),
		"logical_snapshots_observed": 3, "logical_snapshots_equal": true, "proof_query_sets_observed": 2, "proof_query_sets_equal": true,
		"logical_tables_sha256": fmt.Sprintf("%x", sha256.Sum256(tables)), "logical_tables_bytes": len(tables),
		"physical_files_after_final_close":      genesisBuildFiles(dir),
		"actual_chain_Init_Start_Stop_executed": true, "actual_background_batches_executed": true,
		"manager_and_genesis_are_controlled_adapters": true, "source_identifiers_and_suffix_patches_are_synthetic": true,
		"full_node_started": false, "network_executed": false, "signing_or_broadcast_executed": false,
		"accepted_header_root_binding": false, "profile_agreed": false, "production_resources_qualified": false,
		"consumer_result": "REFUSED",
	}
	metadata, err := json.Marshal(observation)
	recoveryMust(err)
	fmt.Fprintf(os.Stderr, "SUCCESSOR_DEFAULT_RETENTION_OBSERVATION=%s\n", metadata)
	fmt.Printf("SUCCESSOR_DEFAULT_RETENTION_TABLES=%s", tables)
}
