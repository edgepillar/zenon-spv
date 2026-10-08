//go:build candidate_chain_startup

// SPDX-License-Identifier: GPL-3.0-only
// Exercise the real chain component startup with finite synthetic inputs.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/zenon-network/go-zenon/chain"
	"github.com/zenon-network/go-zenon/chain/cache/storage"
	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/chain/store"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
)

func init() { chainStartupGenerator = generateChainStartup }

type startupInput struct {
	Name        string `json:"name"`
	SeedFork    string `json:"seed_fork"`
	SeedHeight  uint64 `json:"seed_height"`
	ChainFork   string `json:"chain_fork"`
	ChainHeight uint64 `json:"chain_height"`
	Rounds      int    `json:"rounds"`
}

// Embedded nil interfaces make every unplanned method fail immediately. The
// actual momentum store decodes our serialized snapshots; no ledger insertion,
// VM, genesis transaction, producer, background builder or node service runs.
type startupManager struct {
	db.Manager
	data    db.DB
	patches map[types.HashHeight]db.Patch
	trace   []any
}

func (m *startupManager) Frontier() db.DB {
	m.trace = append(m.trace, map[string]any{"method": "Frontier"})
	return m.data.Snapshot()
}
func (m *startupManager) GetPatch(id types.HashHeight) db.Patch {
	m.trace = append(m.trace, map[string]any{"method": "GetPatch", "identifier": startupID(id)})
	p, ok := m.patches[id]
	require(ok, "unexpected synthetic patch lookup")
	return p
}
func (m *startupManager) Location() string { return "synthetic-memory-chain" }
func (m *startupManager) Stop() error {
	m.trace = append(m.trace, map[string]any{"method": "Stop"})
	return nil
}

type startupCache struct {
	storage.CacheManager
	data  db.DB
	trace []string
}

func (c *startupCache) DB() db.DB {
	c.trace = append(c.trace, "DB")
	return c.data.Snapshot()
}
func (c *startupCache) Stop() error {
	c.trace = append(c.trace, "Stop")
	return nil
}

type startupGenesis struct {
	store.Genesis
	trace []string
}

func (g *startupGenesis) GetGenesisMomentum() *nom.Momentum {
	g.trace = append(g.trace, "GetGenesisMomentum")
	return startupMomentum("A", 1)
}
func (g *startupGenesis) GetSporkAddress() *types.Address {
	g.trace = append(g.trace, "GetSporkAddress")
	a := types.Address{}
	return &a
}

func startupIdentifier(fork string, height uint64) types.HashHeight {
	if fork == "B" && height == 1 {
		fork = "A"
	}
	return types.HashHeight{Height: height,
		Hash: types.NewHash([]byte(fmt.Sprintf("synthetic-chain-startup-v1/%s/%d", fork, height)))}
}
func startupID(id types.HashHeight) any {
	return map[string]any{"hash": id.Hash.String(), "height": id.Height}
}
func startupMomentum(fork string, height uint64) *nom.Momentum {
	i := startupIdentifier(fork, height)
	return &nom.Momentum{Version: 2, Height: height, Hash: i.Hash}
}
func startupKey(missing bool) []byte {
	token := "22222222222222222222"
	if missing {
		token = "44444444444444444444"
	}
	return balanceKey("1111111111111111111111111111111111111111", token)
}
func startupPatch(fork string, height uint64) db.Patch {
	value := make([]byte, 32)
	value[31] = byte(height)
	if fork == "B" && height == 2 {
		value[31] = 22
	}
	if fork == "X" {
		value[31] = 91
	}
	p := db.NewPatch()
	p.Put(startupKey(false), value)
	return p
}
func startupMust(err error) {
	if err != nil {
		panic(err)
	}
}
func startupError(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}
func startupBytes(value []byte) any {
	if value == nil {
		return nil
	}
	return hx(value)
}

func startupSeed(dir string, item startupInput) {
	if item.SeedHeight == 0 {
		return
	}
	ldb, err := leveldb.OpenFile(dir, nil)
	startupMust(err)
	closed := false
	defer func() {
		if !closed {
			ldb.Close()
		}
	}()
	tree, err := trie.NewNodeTree(ldb)
	startupMust(err)
	for h := uint64(1); h <= item.SeedHeight; h++ {
		startupMust(tree.Update(startupPatch(item.SeedFork, h)))
		startupMust(tree.Commit(startupIdentifier(item.SeedFork, h)))
	}
	startupMust(ldb.Close())
	closed = true
}

func startupRound(dir string, item startupInput, round int) any {
	m := &startupManager{data: db.NewMemDB(), patches: map[types.HashHeight]db.Patch{}, trace: []any{}}
	for h := uint64(1); h <= item.ChainHeight; h++ {
		momentum := startupMomentum(item.ChainFork, h)
		serialized, err := momentum.Serialize()
		startupMust(err)
		startupMust(db.SetFrontier(m.data, momentum.Identifier(), serialized))
		m.patches[momentum.Identifier()] = startupPatch(item.ChainFork, h)
	}
	selected := startupIdentifier(item.ChainFork, item.ChainHeight)
	cache := &startupCache{data: db.NewMemDB(), trace: []string{}}
	startupMust(cache.data.Put([]byte{0}, selected.Serialize()))
	g := &startupGenesis{trace: []string{}}
	c := chain.NewChain(m, cache, g, dir, false)
	stopped := false
	defer func() {
		if !stopped {
			c.Stop()
		}
	}()

	// Capture component printf messages in this owned directory. Suppress only
	// its timestamped diagnostic logger in generateChainStartup below. Errors and
	// all method results remain explicit fixture fields. Restore the process
	// stdout and global spork pointer immediately after the isolated Init call.
	log, err := os.OpenFile(filepath.Join(filepath.Dir(dir), fmt.Sprintf("init-%d.log", round)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	startupMust(err)
	savedStdout, savedSpork := os.Stdout, types.SporkAddress
	os.Stdout = log
	initErr := c.Init()
	os.Stdout, types.SporkAddress = savedStdout, savedSpork
	startupMust(log.Close())
	ready := c.StateTreeReady()
	queries := []any{}
	wrong := startupIdentifier("X", item.ChainHeight)
	for _, query := range []struct {
		name string
		id   types.HashHeight
		key  []byte
	}{
		{"root", selected, nil}, {"root-wrong-hash", wrong, nil},
		{"balance", selected, startupKey(false)}, {"balance-wrong-hash", wrong, startupKey(false)},
		{"absent-token", selected, startupKey(true)}, {"compute", selected, nil},
	} {
		row := map[string]any{"name": query.name, "identifier": startupID(query.id), "key": startupBytes(query.key),
			"root": nil, "value": nil, "proof": nil, "error": nil}
		switch query.name {
		case "root", "root-wrong-hash":
			root, err := c.StateRoot(query.id)
			row["root"], row["error"] = root.String(), startupError(err)
		case "compute":
			root, err := c.ComputeStateRoot(query.id, startupPatch("A", 99))
			row["root"], row["error"] = root.String(), startupError(err)
		default:
			value, proof, err := c.GetProof(query.id, query.key)
			row["value"], row["proof"], row["error"] = startupBytes(value), startupBytes(proof), startupError(err)
		}
		queries = append(queries, row)
	}
	startupMust(c.Stop())
	stopped = true
	ldb, err := leveldb.OpenFile(dir, nil)
	startupMust(err)
	closed := false
	defer func() {
		if !closed {
			ldb.Close()
		}
	}()
	tree, err := trie.NewNodeTree(ldb)
	startupMust(err)
	retained := tree.FrontierIdentifier()
	startupMust(ldb.Close())
	closed = true
	return map[string]any{"round": round, "init_error": startupError(initErr), "ready": ready,
		"selected_identifier": startupID(selected), "retained_frontier": startupID(retained), "queries": queries,
		"manager_trace": m.trace, "cache_trace": cache.trace, "genesis_trace": g.trace}
}

func generateChainStartup() any {
	handler := common.ChainLogger.GetHandler()
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	defer common.ChainLogger.SetHandler(handler)
	items := []startupInput{
		{"empty-short", "A", 0, "A", 2, 1},
		{"empty-tail-bound", "A", 0, "A", 10, 1},
		{"empty-tail-plus-one", "A", 0, "A", 11, 1},
		{"matching-prebuild", "A", 2, "A", 2, 1},
		{"same-height-other-hash", "A", 2, "B", 2, 1},
		{"below-matching-ancestor", "A", 1, "A", 2, 1},
		{"below-other-ancestor", "X", 1, "A", 2, 1},
		{"above-matching-retained", "A", 3, "A", 2, 1},
		{"above-divergent-retained", "A", 3, "B", 2, 1},
		{"reopened-divergent-retained", "A", 3, "B", 2, 2},
	}
	cases := []any{}
	for _, item := range items {
		func() {
			root, err := os.MkdirTemp("", "candidate-chain-startup-")
			startupMust(err)
			defer os.RemoveAll(root)
			dir := filepath.Join(root, "state-tree")
			startupSeed(dir, item)
			rounds := []any{}
			for round := 1; round <= item.Rounds; round++ {
				rounds = append(rounds, startupRound(dir, item, round))
			}
			startupMust(os.RemoveAll(root))
			cases = append(cases, map[string]any{"input": item, "rounds": rounds})
		}()
	}
	return map[string]any{"format_version": 1, "kind": "candidate-chain-startup-research",
		"source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"scope": map[string]bool{"synthetic": true, "unsigned": true, "actual_chain_component_Init_executed": true,
			"actual_chain_stateTree_executed": true, "actual_momentum_store_executed": true, "recording_manager_cache_genesis_inputs": true,
			"small_temporary_disk_LevelDB": true, "databases_closed_and_removed": true, "controlled_clean_reopen_executed": true,
			"component_init_messages_discarded": true, "chain_Start_executed": false, "background_build_executed": false,
			"full_node_started": false, "node_tests_executed": false, "network_execution": false, "RPC_executed": false,
			"signing": false, "transactions": false, "crash_recovery_qualified": false, "pruning_qualified": false,
			"retention_resource_budgets_qualified": false, "header_authentication_executed": false,
			"profile_agreed": false, "network_activation_authenticated": false, "runtime_state_proof_acceptance": false},
		"cases": cases}
}
