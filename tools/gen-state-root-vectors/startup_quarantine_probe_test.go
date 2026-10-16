//go:build candidate_startup_quarantine

// SPDX-License-Identifier: GPL-3.0-only
// An isolated probe of the real chain component. It never calls Chain.Start.
package chain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/inconshreveable/log15"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/zenon-network/go-zenon/chain/cache/storage"
	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/chain/store"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
)

type quarantineManager struct {
	db.Manager
	data    db.DB
	patches map[types.HashHeight]db.Patch
	trace   []any
}

func (m *quarantineManager) Frontier() db.DB {
	m.trace = append(m.trace, map[string]any{"method": "Frontier"})
	return m.data.Snapshot()
}
func (m *quarantineManager) GetPatch(id types.HashHeight) db.Patch {
	m.trace = append(m.trace, map[string]any{"method": "GetPatch", "identifier": quarantineID(id)})
	p, ok := m.patches[id]
	if !ok {
		panic("unselected patch request")
	}
	return p
}
func (m *quarantineManager) Location() string { return "synthetic-quarantine-chain" }
func (m *quarantineManager) Stop() error {
	m.trace = append(m.trace, map[string]any{"method": "Stop"})
	return nil
}

type quarantineCache struct {
	storage.CacheManager
	data  db.DB
	trace []string
}

func (c *quarantineCache) DB() db.DB   { c.trace = append(c.trace, "DB"); return c.data.Snapshot() }
func (c *quarantineCache) Stop() error { c.trace = append(c.trace, "Stop"); return nil }

type quarantineGenesis struct {
	store.Genesis
	trace []string
}

func (g *quarantineGenesis) GetGenesisMomentum() *nom.Momentum {
	g.trace = append(g.trace, "GetGenesisMomentum")
	return quarantineMomentum("A", 1)
}
func (g *quarantineGenesis) GetSporkAddress() *types.Address {
	g.trace = append(g.trace, "GetSporkAddress")
	a := types.Address{}
	return &a
}
func quarantineMust(err error) {
	if err != nil {
		panic(err)
	}
}
func quarantineID(id types.HashHeight) any {
	return map[string]any{"height": id.Height, "hash": id.Hash.String()}
}
func quarantineIdentifier(fork string, height uint64) types.HashHeight {
	if fork == "B" && height == 1 {
		fork = "A"
	}
	return types.HashHeight{Height: height, Hash: types.NewHash([]byte(fmt.Sprintf("synthetic-chain-startup-v1/%s/%d", fork, height)))}
}
func quarantineMomentum(fork string, height uint64) *nom.Momentum {
	id := quarantineIdentifier(fork, height)
	return &nom.Momentum{Version: 2, Height: height, Hash: id.Hash}
}
func quarantineKey(absent bool) []byte {
	// L1BalanceKeyPrefix || address[20] || BalanceKeyPrefix || token[10].
	key := make([]byte, 32)
	key[0] = 0x03
	key[21] = 0x03
	for i := 1; i <= 20; i++ {
		key[i] = 0x11
	}
	for i := 22; i < 32; i++ {
		if absent {
			key[i] = 0x44
		} else {
			key[i] = 0x22
		}
	}
	return key
}
func quarantinePatch(fork string, height uint64) db.Patch {
	value := make([]byte, 32)
	value[31] = byte(height)
	if fork == "B" && height == 2 {
		value[31] = 22
	}
	if fork == "X" {
		value[31] = 91
	}
	p := db.NewPatch()
	p.Put(quarantineKey(false), value)
	return p
}
func quarantineBytes(raw []byte) any {
	if raw == nil {
		return nil
	}
	return hex.EncodeToString(raw)
}
func quarantineError(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}
func quarantineRecords(ldb *leveldb.DB) []any {
	rows := []any{}
	it := ldb.NewIterator(nil, nil)
	for it.Next() {
		rows = append(rows, map[string]any{"key": hex.EncodeToString(it.Key()), "value": hex.EncodeToString(it.Value())})
	}
	err := it.Error()
	it.Release()
	quarantineMust(err)
	return rows
}
func quarantineDiskRecords(dir string) []any {
	ldb, err := leveldb.OpenFile(dir, nil)
	quarantineMust(err)
	rows := quarantineRecords(ldb)
	quarantineMust(ldb.Close())
	return rows
}
func quarantineSeed(dir, fork string, height uint64) {
	ldb, err := leveldb.OpenFile(dir, nil)
	quarantineMust(err)
	defer func() { quarantineMust(ldb.Close()) }()
	tree, err := trie.NewNodeTree(ldb)
	quarantineMust(err)
	for h := uint64(1); h <= height; h++ {
		quarantineMust(tree.Update(quarantinePatch(fork, h)))
		quarantineMust(tree.Commit(quarantineIdentifier(fork, h)))
	}
}
func quarantineSelect(m *quarantineManager, c *quarantineCache, fork string, height uint64) {
	m.data = db.NewMemDB()
	m.patches = map[types.HashHeight]db.Patch{}
	m.trace = []any{}
	for h := uint64(1); h <= height; h++ {
		momentum := quarantineMomentum(fork, h)
		raw, err := momentum.Serialize()
		quarantineMust(err)
		quarantineMust(db.SetFrontier(m.data, momentum.Identifier(), raw))
		m.patches[momentum.Identifier()] = quarantinePatch(fork, h)
	}
	c.data = db.NewMemDB()
	c.trace = []string{}
	selected := quarantineIdentifier(fork, height)
	quarantineMust(c.data.Put([]byte{0}, selected.Serialize()))
}
func quarantineQueries(c *chain, selected types.HashHeight) []any {
	rows := []any{}
	wrong := quarantineIdentifier("X", selected.Height)
	for _, q := range []struct {
		name string
		id   types.HashHeight
		key  []byte
	}{
		{"root", selected, nil}, {"root-wrong-hash", wrong, nil},
		{"balance", selected, quarantineKey(false)}, {"balance-wrong-hash", wrong, quarantineKey(false)},
		{"absent-token", selected, quarantineKey(true)}, {"compute", selected, nil},
	} {
		row := map[string]any{"name": q.name, "identifier": quarantineID(q.id), "key": quarantineBytes(q.key), "root": nil, "value": nil, "proof": nil, "error": nil}
		switch q.name {
		case "root", "root-wrong-hash":
			root, err := c.StateRoot(q.id)
			row["root"], row["error"] = root.String(), quarantineError(err)
		case "compute":
			root, err := c.ComputeStateRoot(q.id, quarantinePatch("A", 99))
			row["root"], row["error"] = root.String(), quarantineError(err)
		default:
			value, proof, err := c.GetProof(q.id, q.key)
			row["value"], row["proof"], row["error"] = quarantineBytes(value), quarantineBytes(proof), quarantineError(err)
		}
		rows = append(rows, row)
	}
	return rows
}

type quarantineInput struct {
	Name        string `json:"name"`
	SeedFork    string `json:"seed_fork"`
	SeedHeight  uint64 `json:"seed_height"`
	ChainFork   string `json:"chain_fork"`
	ChainHeight uint64 `json:"chain_height"`
	Rounds      int    `json:"rounds"`
	PrimeReady  bool   `json:"prime_ready"`
}

func quarantineRound(t *testing.T, dir string, item quarantineInput, round int) any {
	t.Helper()
	m := &quarantineManager{}
	cache := &quarantineCache{}
	genesis := &quarantineGenesis{}
	quarantineSelect(m, cache, item.ChainFork, item.ChainHeight)
	c := NewChain(m, cache, genesis, dir, false)
	stopped := false
	defer func() {
		if !stopped {
			quarantineMust(c.Stop())
		}
	}()
	before := quarantineDiskRecords(dir)
	phases := []any{}
	run := func(fork string, height uint64, prime bool) {
		genesis.trace = []string{}
		m.trace = []any{}
		cache.trace = []string{}
		if c.stateTree.ldb != nil {
			before = quarantineRecords(c.stateTree.ldb)
		}
		capture, err := os.OpenFile(filepath.Join(filepath.Dir(dir), fmt.Sprintf("init-%d-%d.log", round, len(phases))), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		quarantineMust(err)
		savedOut, savedSpork := os.Stdout, types.SporkAddress
		var initErr error
		func() {
			defer func() {
				os.Stdout, types.SporkAddress = savedOut, savedSpork
				quarantineMust(capture.Close())
			}()
			os.Stdout = capture
			initErr = c.Init()
		}()
		selected := quarantineIdentifier(fork, height)
		phase := map[string]any{"prime": prime, "init_error": quarantineError(initErr), "ready": c.StateTreeReady(),
			"selected_identifier": quarantineID(selected), "retained_frontier": quarantineID(c.stateTree.tree.FrontierIdentifier()),
			"queries": quarantineQueries(c, selected), "records_before": before, "records_after": quarantineRecords(c.stateTree.ldb),
			"manager_trace": m.trace, "cache_trace": cache.trace, "genesis_trace": genesis.trace}
		if prime && (initErr != nil || !c.StateTreeReady()) {
			t.Fatal("selected priming call did not establish readiness")
		}
		phases = append(phases, phase)
	}
	if item.PrimeReady {
		quarantineSelect(m, cache, item.SeedFork, item.SeedHeight)
		run(item.SeedFork, item.SeedHeight, true)
		quarantineSelect(m, cache, item.ChainFork, item.ChainHeight)
	}
	run(item.ChainFork, item.ChainHeight, false)
	quarantineMust(c.Stop())
	stopped = true
	last := phases[len(phases)-1].(map[string]any)
	last["manager_trace"], last["cache_trace"] = m.trace, cache.trace
	reopened := quarantineDiskRecords(dir)
	return map[string]any{"round": round, "phases": phases, "records_after_close_reopen": reopened}
}
func TestCandidateStartupQuarantine(t *testing.T) {
	variant := os.Getenv("ZENON_STARTUP_VARIANT")
	if variant != "baseline" && variant != "startup-quarantine" {
		t.Fatal("select one explicit source variant")
	}
	handler := common.ChainLogger.GetHandler()
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	defer common.ChainLogger.SetHandler(handler)
	items := []quarantineInput{
		{"empty-short", "A", 0, "A", 2, 1, false},
		{"empty-tail-bound", "A", 0, "A", 10, 1, false},
		{"empty-tail-plus-one", "A", 0, "A", 11, 1, false},
		{"matching-prebuild", "A", 2, "A", 2, 1, false},
		{"same-height-other-hash", "A", 2, "B", 2, 1, false},
		{"below-matching-ancestor", "A", 1, "A", 2, 1, false},
		{"below-other-ancestor", "X", 1, "A", 2, 1, false},
		{"above-matching-retained", "A", 3, "A", 2, 1, false},
		{"above-divergent-retained", "A", 3, "B", 2, 1, false},
		{"reopened-divergent-retained", "A", 3, "B", 2, 2, false},
		{"previously-ready-divergent", "A", 3, "B", 2, 1, true},
		{"previously-ready-same-height-other-hash", "A", 3, "B", 3, 1, true},
	}
	cases := []any{}
	for _, item := range items {
		dir := filepath.Join(t.TempDir(), "tree")
		quarantineSeed(dir, item.SeedFork, item.SeedHeight)
		rounds := []any{}
		for round := 1; round <= item.Rounds; round++ {
			rounds = append(rounds, quarantineRound(t, dir, item, round))
		}
		cases = append(cases, map[string]any{"input": item, "rounds": rounds})
	}
	document := map[string]any{"format_version": 1, "kind": "candidate-startup-quarantine-research", "variant": variant, "cases": cases}
	raw, err := json.Marshal(document)
	quarantineMust(err)
	fmt.Printf("STARTUP_QUARANTINE=%s\n", raw)
}
