//go:build candidate_genesis_background

// SPDX-License-Identifier: GPL-3.0-only
// A real chain/stateTree worker on source-derived state and unsigned fixture history.
package chain

import (
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
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

const genesisBuildHeight = uint64(4096)
const genesisBuildInputSHA = "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75"

type genesisBuildGenesis struct{ recoveryGenesis }

func (g *genesisBuildGenesis) GetGenesisMomentum() *nom.Momentum {
	return recoveryMomentum("G", 1)
}
func (g *genesisBuildGenesis) ChainIdentifier() uint64 { return 1 }

type genesisBuildManager struct {
	*recoveryManager
	entered, release chan struct{}
	once             sync.Once
	calls            map[uint64]int
}

func (m *genesisBuildManager) GetPatch(id types.HashHeight) db.Patch {
	if id != recoveryIdentifier("G", id.Height) || id.Height < 1 || id.Height > genesisBuildHeight {
		panic("unselected history identifier")
	}
	m.calls[id.Height]++
	p := m.recoveryManager.GetPatch(id)
	if m.entered != nil && id.Height == 1 {
		m.once.Do(func() { close(m.entered); <-m.release })
	}
	return p
}

type genesisBuildApply struct {
	db  db.DB
	err error
}

func (a *genesisBuildApply) Put(k, v []byte) {
	if a.err == nil {
		a.err = a.db.Put(k, v)
	}
}
func (a *genesisBuildApply) Delete(k []byte) {
	if a.err == nil {
		a.err = a.db.Delete(k)
	}
}

type genesisBuildSample struct {
	Selection string `json:"selection"`
	RawKey    string `json:"raw_key"`
}
type genesisBuildExpectations struct {
	SelectedProofs []genesisBuildSample `json:"selected_proofs"`
}

func genesisBuildRead(path string, limit int64) []byte {
	f, err := os.Open(path)
	recoveryMust(err)
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	recoveryMust(err)
	if int64(len(raw)) > limit {
		panic("selected input exceeds bound")
	}
	return raw
}
func genesisBuildInputs() (db.Patch, []genesisBuildSample, [][]byte) {
	raw := genesisBuildRead(os.Getenv("ZENON_GENESIS_BUILD_INPUT"), 32<<20)
	if len(raw) != 10849399 || fmt.Sprintf("%x", sha256.Sum256(raw)) != genesisBuildInputSHA {
		panic("source genesis input identity mismatch")
	}
	p, err := db.NewPatchFromDump(raw)
	recoveryMust(err)
	encoded := genesisBuildRead(os.Getenv("ZENON_GENESIS_BUILD_SAMPLES"), 1<<20)
	var samples genesisBuildExpectations
	recoveryMust(json.Unmarshal(encoded, &samples))
	if len(samples.SelectedProofs) != 15 {
		panic("incomplete selected proof inventory")
	}
	keys := [][]byte{}
	for _, row := range samples.SelectedProofs {
		key, err := hex.DecodeString(row.RawKey)
		recoveryMust(err)
		if row.Selection == "balance" {
			if len(key) != 32 {
				panic("invalid balance key")
			}
			keys = append(keys, key)
		}
	}
	if len(keys) != 8 {
		panic("incomplete mutation key inventory")
	}
	return p, samples.SelectedProofs, keys
}
func genesisBuildPatch(height uint64, keys [][]byte) db.Patch {
	p := db.NewPatch()
	key := keys[(height-2)%8]
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
func genesisBuildFixture(initial db.Patch, keys [][]byte) (*genesisBuildManager, *recoveryCache, *genesisBuildGenesis) {
	r := &recoveryManager{}
	cache := &recoveryCache{}
	recoverySelect(r, cache, "G", genesisBuildHeight)
	for h := uint64(1); h <= genesisBuildHeight; h++ {
		p := initial
		if h > 1 {
			p = genesisBuildPatch(h, keys)
		}
		r.patches[recoveryIdentifier("G", h)] = p
		applied := &genesisBuildApply{db: r.data}
		recoveryMust(p.Replay(applied))
		recoveryMust(applied.err)
		momentum := recoveryMomentum("G", h)
		encoded, err := momentum.Serialize()
		recoveryMust(err)
		recoveryMust(db.SetFrontier(r.data, momentum.Identifier(), encoded))
	}
	return &genesisBuildManager{recoveryManager: r, calls: map[uint64]int{}}, cache, &genesisBuildGenesis{}
}
func genesisBuildWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(180 * time.Second):
		t.Fatal("selected background worker did not finish")
	}
}
func genesisBuildStopResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(180 * time.Second):
		t.Fatal("selected Stop did not return")
		return nil
	}
}
func genesisBuildSnapshot(ldb *leveldb.DB) map[string]any {
	sum := sha256.New()
	var size [8]byte
	prefix := map[string]int{}
	roots := map[uint64]string{}
	identities := map[uint64]string{}
	count := 0
	logicalBytes := uint64(0)
	format := ""
	it := ldb.NewIterator(nil, nil)
	for it.Next() {
		k, v := it.Key(), it.Value()
		count++
		logicalBytes += uint64(len(k) + len(v))
		binary.BigEndian.PutUint64(size[:], uint64(len(k)))
		_, _ = sum.Write(size[:])
		_, _ = sum.Write(k)
		binary.BigEndian.PutUint64(size[:], uint64(len(v)))
		_, _ = sum.Write(size[:])
		_, _ = sum.Write(v)
		if len(k) == 0 {
			panic("empty node storage key")
		}
		prefix[fmt.Sprintf("%02x", k[0])]++
		if len(k) == 9 && k[0] == 3 {
			if len(v) != 32 {
				panic("invalid root record")
			}
			roots[binary.BigEndian.Uint64(k[1:])] = hex.EncodeToString(v)
		}
		if len(k) == 9 && k[0] == 6 {
			if len(v) != 32 {
				panic("invalid identity record")
			}
			identities[binary.BigEndian.Uint64(k[1:])] = hex.EncodeToString(v)
		}
		if len(k) == 1 && k[0] == 5 {
			format = hex.EncodeToString(v)
		}
	}
	err := it.Error()
	it.Release()
	recoveryMust(err)
	heights := make([]uint64, 0, len(roots))
	for h := range roots {
		heights = append(heights, h)
	}
	sort.Slice(heights, func(i, j int) bool { return heights[i] < heights[j] })
	if len(roots) != len(identities) || format != "03" {
		panic("unpaired or unexpected node storage metadata")
	}
	rows := []any{}
	for _, h := range heights {
		id := recoveryIdentifier("G", h)
		if identities[h] != id.Hash.String() {
			panic("retained identity differs from selected source history")
		}
		rows = append(rows, map[string]any{"height": h, "root": roots[h], "hash": identities[h]})
	}
	return map[string]any{"logical_records": count, "logical_key_value_bytes": logicalBytes, "logical_records_sha256": hex.EncodeToString(sum.Sum(nil)), "record_prefix_counts": prefix, "format": format, "retained_roots": rows}
}
func genesisBuildClosedSnapshot(dir string) map[string]any {
	ldb, err := leveldb.OpenFile(dir, &opt.Options{ReadOnly: true})
	recoveryMust(err)
	result := genesisBuildSnapshot(ldb)
	recoveryMust(ldb.Close())
	return result
}
func genesisBuildQueries(c *chain, samples []genesisBuildSample) []any {
	result := []any{}
	for _, h := range []uint64{1, 3840, 3841, 3968, 4096} {
		id := recoveryIdentifier("G", h)
		root, err := c.StateRoot(id)
		proofs := []any{}
		for _, sample := range samples {
			key, e := hex.DecodeString(sample.RawKey)
			recoveryMust(e)
			value, proof, e := c.GetProof(id, key)
			proofs = append(proofs, map[string]any{"selection": sample.Selection, "raw_key": sample.RawKey, "value": recoveryBytes(value), "proof": recoveryBytes(proof), "error": recoveryError(e), "consumer_result": "REFUSED"})
		}
		result = append(result, map[string]any{"height": h, "root": root.String(), "root_error": recoveryError(err), "proofs": proofs})
	}
	for _, id := range []types.HashHeight{recoveryIdentifier("G", 3839), recoveryIdentifier("X", 4096), types.ZeroHashHeight} {
		root, err := c.StateRoot(id)
		result = append(result, map[string]any{"identifier": recoveryID(id), "root": root.String(), "root_error": recoveryError(err)})
	}
	return result
}
func genesisBuildFiles(dir string) []any {
	files, err := os.ReadDir(dir)
	recoveryMust(err)
	rows := []any{}
	for _, entry := range files {
		info, err := entry.Info()
		recoveryMust(err)
		if !info.Mode().IsRegular() || info.Size() > 256<<20 {
			panic("unexpected generated physical node file")
		}
		f, err := os.Open(filepath.Join(dir, entry.Name()))
		recoveryMust(err)
		hash := sha256.New()
		n, err := io.Copy(hash, io.LimitReader(f, (256<<20)+1))
		closeErr := f.Close()
		recoveryMust(err)
		recoveryMust(closeErr)
		if n != info.Size() {
			panic("node file length changed after close")
		}
		rows = append(rows, map[string]any{"name": entry.Name(), "bytes": n, "sha256": hex.EncodeToString(hash.Sum(nil))})
	}
	return rows
}
func TestCandidateGenesisBackground(t *testing.T) {
	policy := os.Getenv("ZENON_GENESIS_BUILD_POLICY")
	if policy != "archive" && policy != "pruned" && policy != "stop-resume" {
		t.Fatal("select one declared background policy")
	}
	parent := os.Getenv("ZENON_GENESIS_BUILD_WORKSPACE")
	if parent == "" {
		t.Fatal("select a new caller-owned work root")
	}
	dir := filepath.Join(parent, "node")
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("existing node directory refused")
	}
	initial, samples, keys := genesisBuildInputs()
	handler := common.ChainLogger.GetHandler()
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	defer common.ChainLogger.SetHandler(handler)
	oldSpork := types.SporkAddress
	defer func() { types.SporkAddress = oldSpork }()
	totalStart := time.Now()
	started := totalStart
	m, cache, genesis := genesisBuildFixture(initial, keys)
	setupNS := time.Since(started).Nanoseconds()
	archive := policy == "archive"
	c := NewChain(m, cache, genesis, dir, archive)
	c.stateTree.retentionOverride = 256
	stopped := false
	defer func() {
		if m.release != nil {
			select {
			case <-m.release:
			default:
				close(m.release)
			}
		}
		if !stopped {
			_ = c.Stop()
		}
	}()
	if policy == "stop-resume" {
		c.stateTree.bulkBatchOverride = 1
		m.entered = make(chan struct{})
		m.release = make(chan struct{})
	}
	started = time.Now()
	recoveryMust(c.Init())
	initNS := time.Since(started).Nanoseconds()
	if c.StateTreeReady() {
		t.Fatal("a large gap became ready before the selected worker")
	}
	initialReads := map[string]any{}
	r, e := c.StateRoot(recoveryIdentifier("G", 4096))
	initialReads["root"] = r.String()
	initialReads["error"] = recoveryError(e)
	started = time.Now()
	recoveryMust(c.Start())
	exit := c.stateTree.buildExited
	if exit == nil {
		t.Fatal("worker exit handle was not published")
	}
	var interrupted any
	if policy == "stop-resume" {
		genesisBuildWait(t, m.entered)
		stopDone := make(chan error, 1)
		go func() { stopDone <- c.Stop() }()
		genesisBuildWait(t, c.stateTree.quit)
		select {
		case <-stopDone:
			t.Fatal("Stop returned while the selected manager gate held changes")
		default:
		}
		if c.StateTreeReady() {
			t.Fatal("stop intent did not revoke readiness")
		}
		close(m.release)
		recoveryMust(genesisBuildStopResult(t, stopDone))
		stopped = true
		genesisBuildWait(t, exit)
		rawRoot, closedErr := c.stateTree.tree.Root(recoveryIdentifier("G", 1))
		interrupted = map[string]any{"frontier": recoveryID(c.stateTree.tree.FrontierIdentifier()), "ready": c.StateTreeReady(), "direct_closed_root": rawRoot.String(), "direct_closed_error": recoveryError(closedErr), "closed_snapshot": genesisBuildClosedSnapshot(dir)}
		c = NewChain(m, cache, genesis, dir, false)
		c.stateTree.retentionOverride = 256
		stopped = false
		recoveryMust(c.Init())
		if c.StateTreeReady() {
			t.Fatal("interrupted gap did not require continuation")
		}
		recoveryMust(c.Start())
		exit = c.stateTree.buildExited
	}
	genesisBuildWait(t, exit)
	workerNS := time.Since(started).Nanoseconds()
	if !c.StateTreeReady() || c.stateTree.tree.FrontierIdentifier() != recoveryIdentifier("G", 4096) {
		t.Fatal("worker did not reach the exact selected frontier")
	}
	before := genesisBuildSnapshot(c.stateTree.ldb)
	queries := genesisBuildQueries(c, samples)
	started = time.Now()
	recoveryMust(c.Stop())
	stopped = true
	stopNS := time.Since(started).Nanoseconds()
	publicRoot, publicErr := c.StateRoot(recoveryIdentifier("G", 4096))
	rawRoot, rawErr := c.stateTree.tree.Root(recoveryIdentifier("G", 4096))
	afterStop := genesisBuildClosedSnapshot(dir)
	started = time.Now()
	c = NewChain(m, cache, genesis, dir, archive)
	c.stateTree.retentionOverride = 256
	stopped = false
	recoveryMust(c.Init())
	if !c.StateTreeReady() {
		t.Fatal("clean recovered frontier did not become ready")
	}
	reopened := genesisBuildSnapshot(c.stateTree.ldb)
	reopenedQueries := genesisBuildQueries(c, samples)
	recoveryMust(c.Stop())
	stopped = true
	reopenNS := time.Since(started).Nanoseconds()
	for h := uint64(1); h <= 4096; h++ {
		if m.calls[h] != 1 {
			t.Fatalf("patch %d replayed %d times", h, m.calls[h])
		}
	}
	if len(m.calls) != 4096 {
		t.Fatal("unexpected patch request inventory")
	}
	same := func(a, b any) bool {
		x, err := json.Marshal(a)
		recoveryMust(err)
		y, err := json.Marshal(b)
		recoveryMust(err)
		return string(x) == string(y)
	}
	if !same(before, afterStop) || !same(before, reopened) || !same(queries, reopenedQueries) {
		t.Fatal("logical evidence changed across closed/reopened observation")
	}
	document := map[string]any{"kind": "source-genesis-background-component-observation", "policy": policy, "Go_version": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH,
		"raw_input_sha256": genesisBuildInputSHA, "history_height": 4096, "retention_test_override": 256, "fixture_initialization_ns": setupNS, "component_init_ns": initNS,
		"worker_and_controlled_restart_elapsed_ns": workerNS, "stop_elapsed_ns": stopNS, "clean_reopen_elapsed_ns": reopenNS, "component_workflow_elapsed_ns": time.Since(totalStart).Nanoseconds(),
		"source_identifiers_and_suffix_patches_are_synthetic": true, "initial_reads": initialReads, "interrupted": interrupted, "snapshot_before_stop": before, "closed_snapshot": afterStop,
		"reopened_snapshot": reopened, "queries": queries, "reopened_queries": reopenedQueries, "patch_heights_requested": len(m.calls), "each_patch_requested_once": true,
		"post_stop_public_root": publicRoot.String(), "post_stop_public_error": recoveryError(publicErr), "post_stop_direct_root": rawRoot.String(), "post_stop_direct_error": recoveryError(rawErr),
		"physical_files_after_final_close": genesisBuildFiles(dir), "actual_chain_Init_Start_Stop_executed": true, "actual_background_batches_executed": true,
		"manager_and_genesis_are_controlled_adapters": true, "full_node_started": false, "network_executed": false, "signing_or_broadcast_executed": false,
		"production_concurrency_qualified": false, "profile_agreed": false, "accepted_header_root_binding": false, "consumer_result": "REFUSED"}
	raw, err := json.Marshal(document)
	recoveryMust(err)
	fmt.Printf("GENESIS_BACKGROUND=%s\n", raw)
}
