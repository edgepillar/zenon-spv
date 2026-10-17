//go:build candidate_hash_bound_versions_successor

// SPDX-License-Identifier: GPL-3.0-only
// An isolated probe of the real chain component. It never calls Chain.Start.
package chain

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

type recoveryManager struct {
	db.Manager
	data    db.DB
	patches map[types.HashHeight]db.Patch
	trace   []any
}

func (m *recoveryManager) Frontier() db.DB {
	m.trace = append(m.trace, map[string]any{"method": "Frontier"})
	return m.data.Snapshot()
}
func (m *recoveryManager) GetPatch(id types.HashHeight) db.Patch {
	m.trace = append(m.trace, map[string]any{"method": "GetPatch", "identifier": recoveryID(id)})
	p, ok := m.patches[id]
	if !ok {
		panic("unselected patch request")
	}
	return p
}
func (m *recoveryManager) Location() string { return "synthetic-hash-bound-chain" }
func (m *recoveryManager) Stop() error {
	m.trace = append(m.trace, map[string]any{"method": "Stop"})
	return nil
}

type recoveryCache struct {
	storage.CacheManager
	data  db.DB
	trace []string
}

func (c *recoveryCache) DB() db.DB   { c.trace = append(c.trace, "DB"); return c.data.Snapshot() }
func (c *recoveryCache) Stop() error { c.trace = append(c.trace, "Stop"); return nil }

type recoveryGenesis struct {
	store.Genesis
	trace []string
}

func (g *recoveryGenesis) GetGenesisMomentum() *nom.Momentum {
	g.trace = append(g.trace, "GetGenesisMomentum")
	return recoveryMomentum("A", 1)
}
func (g *recoveryGenesis) GetSporkAddress() *types.Address {
	g.trace = append(g.trace, "GetSporkAddress")
	a := types.Address{}
	return &a
}
func recoveryMust(err error) {
	if err != nil {
		panic(err)
	}
}
func recoveryID(id types.HashHeight) any {
	return map[string]any{"height": id.Height, "hash": id.Hash.String()}
}
func recoveryIdentifier(fork string, height uint64) types.HashHeight {
	if fork == "B" && height == 1 {
		fork = "A"
	}
	return types.HashHeight{Height: height, Hash: types.NewHash([]byte(fmt.Sprintf("synthetic-hash-bound-node-v1/%s/%d", fork, height)))}
}
func recoveryMomentum(fork string, height uint64) *nom.Momentum {
	id := recoveryIdentifier(fork, height)
	return &nom.Momentum{Version: 2, Height: height, Hash: id.Hash}
}
func recoveryKey(absent bool) []byte {
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
func recoveryPatch(fork string, height uint64) db.Patch {
	value := make([]byte, 32)
	value[31] = byte(height)
	if fork == "B" && height == 2 {
		value[31] = 22
	}
	if fork == "X" {
		value[31] = 91
	}
	p := db.NewPatch()
	p.Put(recoveryKey(false), value)
	if fork == "B" && height == 2 {
		secondary := make([]byte, 32)
		secondary[31] = 222
		p.Put(recoverySecondaryKey(), secondary)
	}
	return p
}
func recoveryBytes(raw []byte) any {
	if raw == nil {
		return nil
	}
	return hex.EncodeToString(raw)
}
func recoveryError(err error) any {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, trie.ErrFormatMismatch):
		return "format-mismatch"
	case errors.Is(err, trie.ErrNoVersion):
		return "no-version"
	case errors.Is(err, trie.ErrCorrupt):
		return "corrupt"
	case errors.Is(err, ErrStateTreeNotReady):
		return "not-ready"
	case errors.Is(err, trie.ErrCommitOutOfOrder):
		return "commit-order"
	case errors.Is(err, trie.ErrBulkCommitOutOfOrder):
		return "bulk-order"
	case errors.Is(err, trie.ErrNotStaged):
		return "staging-missing"
	case err.Error() == "trie: retained version Momentum hash mismatch":
		return "version-hash-mismatch"
	case err.Error() == "trie: retained version Momentum hash missing":
		return "version-hash-missing"
	case err.Error() == "trie: cannot prune the current frontier":
		return "prune-frontier"
	case err.Error() == "leveldb: closed":
		return "database-closed"
	case err.Error() == "leveldb: not found":
		return "store-key-missing"
	case err.Error() == "synthetic recovery replay failure":
		return "injected-replay"
	case strings.HasPrefix(err.Error(), "the state tree's state is incorrect."):
		return "wrong-chain-identity"
	}
	// Unexpected diagnostics remain in the private supervised failure stream.
	panic(err)
}
func recoveryRecords(ldb *leveldb.DB) []any {
	rows := []any{}
	it := ldb.NewIterator(nil, nil)
	for it.Next() {
		rows = append(rows, map[string]any{"key": hex.EncodeToString(it.Key()), "value": hex.EncodeToString(it.Value())})
	}
	err := it.Error()
	it.Release()
	recoveryMust(err)
	return rows
}
func recoveryDiskRecords(dir string) []any {
	ldb, err := leveldb.OpenFile(dir, nil)
	recoveryMust(err)
	rows := recoveryRecords(ldb)
	recoveryMust(ldb.Close())
	return rows
}
func recoverySeed(dir, fork string, height uint64) {
	ldb, err := leveldb.OpenFile(dir, nil)
	recoveryMust(err)
	defer func() { recoveryMust(ldb.Close()) }()
	tree, err := trie.NewNodeTree(ldb)
	recoveryMust(err)
	for h := uint64(1); h <= height; h++ {
		recoveryMust(tree.Update(recoveryPatch(fork, h)))
		recoveryMust(tree.Commit(recoveryIdentifier(fork, h)))
	}
}
func recoverySelect(m *recoveryManager, c *recoveryCache, fork string, height uint64) {
	m.data = db.NewMemDB()
	m.patches = map[types.HashHeight]db.Patch{}
	m.trace = []any{}
	for h := uint64(1); h <= height; h++ {
		momentum := recoveryMomentum(fork, h)
		raw, err := momentum.Serialize()
		recoveryMust(err)
		recoveryMust(db.SetFrontier(m.data, momentum.Identifier(), raw))
		m.patches[momentum.Identifier()] = recoveryPatch(fork, h)
	}
	c.data = db.NewMemDB()
	c.trace = []string{}
	selected := recoveryIdentifier(fork, height)
	recoveryMust(c.data.Put([]byte{0}, selected.Serialize()))
}

func recoverySecondaryKey() []byte {
	key := recoveryKey(false)
	for i := 22; i < len(key); i++ {
		key[i] = 0x33
	}
	return key
}

type recoveryCounter struct {
	db.Patch
	dump, replay int
	fail         bool
}

func (p *recoveryCounter) Dump() []byte {
	p.dump++
	return p.Patch.Dump()
}
func (p *recoveryCounter) Replay(out db.PatchReplayer) error {
	p.replay++
	if p.fail {
		return errors.New("synthetic recovery replay failure")
	}
	return p.Patch.Replay(out)
}

type recoveryQuerySource struct {
	root    func(types.HashHeight) (types.Hash, error)
	proof   func(types.HashHeight, []byte) ([]byte, []byte, error)
	compute func(types.HashHeight, db.Patch) (types.Hash, error)
}

func recoveryQueries(q recoveryQuerySource, selected types.HashHeight) []any {
	wrong := recoveryIdentifier("X", selected.Height)
	rows := []any{}
	for _, item := range []struct {
		name string
		id   types.HashHeight
		key  []byte
	}{
		{"root", selected, nil}, {"root-wrong-hash", wrong, nil},
		{"balance", selected, recoveryKey(false)},
		{"balance-wrong-hash", wrong, recoveryKey(false)},
		{"secondary", selected, recoverySecondaryKey()},
		{"absent-token", selected, recoveryKey(true)},
		{"compute", selected, nil}, {"compute-repeat", selected, nil},
		{"compute-wrong-hash", wrong, nil},
		{"origin-root", types.ZeroHashHeight, nil},
		{"origin-wrong-hash", recoveryIdentifier("X", 0), nil},
	} {
		counter := &recoveryCounter{Patch: recoveryPatch("A", 99)}
		row := map[string]any{
			"name": item.name, "identifier": recoveryID(item.id), "key": recoveryBytes(item.key),
			"root": nil, "value": nil, "proof": nil, "error": nil,
		}
		switch {
		case strings.HasPrefix(item.name, "compute"):
			root, err := q.compute(item.id, counter)
			row["root"], row["error"] = root.String(), recoveryError(err)
		case item.name == "root" || item.name == "root-wrong-hash" || strings.HasPrefix(item.name, "origin"):
			root, err := q.root(item.id)
			row["root"], row["error"] = root.String(), recoveryError(err)
		default:
			value, proof, err := q.proof(item.id, item.key)
			row["value"], row["proof"], row["error"] = recoveryBytes(value), recoveryBytes(proof), recoveryError(err)
		}
		row["patch_callbacks"] = map[string]any{"dump": counter.dump, "replay": counter.replay}
		rows = append(rows, row)
	}
	return rows
}

func recoveryVersionKey(prefix byte, height uint64) []byte {
	return common.JoinBytes([]byte{prefix}, common.Uint64ToBytes(height))
}

// Only fresh test fixtures are transformed. This is not a database migration API.
func recoveryFault(dir, fault, fork string, height uint64) {
	if fault == "" {
		return
	}
	ldb, err := leveldb.OpenFile(dir, nil)
	recoveryMust(err)
	defer func() { recoveryMust(ldb.Close()) }()
	switch fault {
	case "legacy-2":
		recoveryMust(ldb.Put([]byte{5}, []byte{2}, nil))
		for h := uint64(1); h <= height; h++ {
			recoveryMust(ldb.Delete(recoveryVersionKey(6, h), nil))
		}
	case "candidate-3":
		recoveryMust(ldb.Put([]byte{5}, []byte{3}, nil))
		for h := uint64(1); h <= height; h++ {
			id := recoveryIdentifier(fork, h)
			recoveryMust(ldb.Put(recoveryVersionKey(6, h), id.Hash[:], nil))
		}
	case "foreign-4":
		recoveryMust(ldb.Put([]byte{5}, []byte{4}, nil))
	case "frontier-hash":
		id := recoveryIdentifier("B", height)
		recoveryMust(ldb.Put([]byte{0}, id.Bytes(), nil))
	case "missing-frontier-hash":
		recoveryMust(ldb.Delete(recoveryVersionKey(6, height), nil))
	case "short-frontier-hash":
		recoveryMust(ldb.Put(recoveryVersionKey(6, height), make([]byte, 31), nil))
	case "missing-historical-hash":
		recoveryMust(ldb.Delete(recoveryVersionKey(6, 1), nil))
	case "missing-root-node":
		root, err := ldb.Get(recoveryVersionKey(3, height), nil)
		recoveryMust(err)
		recoveryMust(ldb.Delete(append([]byte{1}, root...), nil))
	case "missing-secondary-node":
		value := make([]byte, 32)
		value[31] = 222
		id := trie.LeafHash(types.NewHash(recoverySecondaryKey()), value)
		recoveryMust(ldb.Delete(common.JoinBytes([]byte{1}, id[:]), nil))
	case "missing-primary-node":
		value := make([]byte, 32)
		value[31] = byte(height)
		id := trie.LeafHash(types.NewHash(recoveryKey(false)), value)
		recoveryMust(ldb.Delete(common.JoinBytes([]byte{1}, id[:]), nil))
	default:
		panic("unselected recovery fault")
	}
}

type recoveryInput struct {
	Name        string `json:"name"`
	SeedFork    string `json:"seed_fork"`
	SeedHeight  uint64 `json:"seed_height"`
	ChainFork   string `json:"chain_fork"`
	ChainHeight uint64 `json:"chain_height"`
	Rounds      int    `json:"rounds"`
	PrimeReady  bool   `json:"prime_ready"`
	Fault       string `json:"fault"`
	Action      string `json:"action"`
	QueryFork   string `json:"query_fork"`
	QueryHeight uint64 `json:"query_height"`
}

func recoveryRound(t *testing.T, dir string, item recoveryInput, round int) any {
	t.Helper()
	m := &recoveryManager{}
	cache := &recoveryCache{}
	genesis := &recoveryGenesis{}
	recoverySelect(m, cache, item.ChainFork, item.ChainHeight)
	c := NewChain(m, cache, genesis, dir, false)
	stopped, backendClosed := false, false
	defer func() {
		if !stopped {
			err := c.Stop()
			if !backendClosed {
				recoveryMust(err)
			}
		}
	}()
	records := func() []any {
		if c.stateTree.ldb != nil && !backendClosed {
			return recoveryRecords(c.stateTree.ldb)
		}
		return recoveryDiskRecords(dir)
	}
	phases := []any{}
	run := func(fork string, height uint64, prime bool) {
		before := records()
		m.trace, cache.trace, genesis.trace = []any{}, []string{}, []string{}
		capture, err := os.OpenFile(filepath.Join(filepath.Dir(dir), fmt.Sprintf("init-%d-%d.log", round, len(phases))), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		recoveryMust(err)
		savedOut, savedSpork := os.Stdout, types.SporkAddress
		var initErr error
		func() {
			defer func() {
				os.Stdout, types.SporkAddress = savedOut, savedSpork
				recoveryMust(capture.Close())
			}()
			os.Stdout = capture
			initErr = c.Init()
		}()
		afterInit := records()
		if prime && (initErr != nil || !c.StateTreeReady()) {
			t.Fatal("selected priming initialization failed")
		}
		var frontier any
		if c.stateTree.tree != nil {
			frontier = recoveryID(c.stateTree.tree.FrontierIdentifier())
		}
		var action any
		if !prime && item.Action != "" {
			if initErr != nil || !c.StateTreeReady() {
				t.Fatal("action requires selected initialized tree")
			}
			warm := recoveryIdentifier("A", 3)
			if item.Action == "cache-prune" {
				warm = recoveryIdentifier("A", 1)
			}
			counter := &recoveryCounter{Patch: recoveryPatch("A", 99)}
			root, warmErr := c.ComputeStateRoot(warm, counter)
			recoveryMust(warmErr)
			var actionErr error
			switch item.Action {
			case "cache-prune":
				c.stateTree.changes.Lock()
				c.stateTree.retentionOverride = 1
				actionErr = c.stateTree.prune()
				c.stateTree.changes.Unlock()
			case "cache-truncate":
				insert := c.AcquireInsert("synthetic hash-bound-version truncate")
				actionErr = c.TruncateStateTreeTo(insert, recoveryIdentifier("A", 2))
				insert.Unlock()
			case "cache-close":
				actionErr = c.stateTree.ldb.Close()
				backendClosed = true
			default:
				panic("unselected cache action")
			}
			action = map[string]any{
				"name": item.Action, "warm_identifier": recoveryID(warm),
				"warm_root": root.String(), "warm_error": recoveryError(warmErr),
				"warm_patch_callbacks": map[string]any{"dump": counter.dump, "replay": counter.replay},
				"error":                recoveryError(actionErr), "records_after": records(),
			}
			frontier = recoveryID(c.stateTree.tree.FrontierIdentifier())
		}
		query := recoveryIdentifier(fork, height)
		if item.QueryFork != "" {
			query = recoveryIdentifier(item.QueryFork, item.QueryHeight)
		}
		phases = append(phases, map[string]any{
			"prime": prime, "selected_identifier": recoveryID(recoveryIdentifier(fork, height)),
			"query_identifier": recoveryID(query), "init_error": recoveryError(initErr),
			"ready": c.StateTreeReady(), "retained_frontier": frontier,
			"handle_open": c.stateTree.ldb != nil, "action": action,
			"records_before": before, "records_after_init": afterInit,
			"queries":               recoveryQueries(recoveryQuerySource{c.StateRoot, c.GetProof, c.ComputeStateRoot}, query),
			"records_after_queries": records(), "manager_trace": m.trace,
			"cache_trace": cache.trace, "genesis_trace": genesis.trace,
		})
	}
	if item.PrimeReady {
		recoverySelect(m, cache, item.SeedFork, item.SeedHeight)
		run(item.SeedFork, item.SeedHeight, true)
		recoverySelect(m, cache, item.ChainFork, item.ChainHeight)
	}
	run(item.ChainFork, item.ChainHeight, false)
	stopErr := c.Stop()
	stopped = true
	if stopErr != nil && !backendClosed {
		t.Fatal(stopErr)
	}
	return map[string]any{
		"round": round, "phases": phases, "stop_error": recoveryError(stopErr),
		"ready_after_stop":           c.StateTreeReady(),
		"records_after_close_reopen": recoveryDiskRecords(dir),
		"final_manager_trace":        m.trace, "final_cache_trace": cache.trace,
	}
}

func recoveryLowLevel(t *testing.T, name string) any {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tree")
	ldb, err := leveldb.OpenFile(dir, nil)
	recoveryMust(err)
	tree, err := trie.NewNodeTree(ldb)
	recoveryMust(err)
	ops := []any{}
	record := func(method string, id types.HashHeight, resultRoot any, opErr error, counter *recoveryCounter) {
		row := map[string]any{"method": method, "identifier": recoveryID(id), "root": resultRoot, "error": recoveryError(opErr)}
		if counter != nil {
			row["patch_callbacks"] = map[string]any{"dump": counter.dump, "replay": counter.replay}
		}
		ops = append(ops, row)
	}
	if name == "bulk-gap" {
		for h := uint64(1); h <= 5; h++ {
			recoveryMust(tree.AccumulateFrom(recoveryPatch("A", h)))
		}
		recoveryMust(tree.CommitBulk(recoveryIdentifier("A", 5)))
	} else if name == "empty-version" {
		recoveryMust(tree.Update(db.NewPatch()))
		recoveryMust(tree.Commit(recoveryIdentifier("A", 1)))
	} else if name == "commit-origin-after-max" {
		recoveryMust(tree.AccumulateFrom(recoveryPatch("A", 1)))
		recoveryMust(tree.CommitBulk(recoveryIdentifier("A", ^uint64(0))))
	} else {
		for h := uint64(1); h <= 3; h++ {
			recoveryMust(tree.Update(recoveryPatch("A", h)))
			recoveryMust(tree.Commit(recoveryIdentifier("A", h)))
		}
	}
	before := recoveryRecords(ldb)
	target := recoveryIdentifier("A", 3)
	switch name {
	case "queries":
	case "truncate-matching":
		target = recoveryIdentifier("A", 2)
		record("Truncate", target, nil, tree.Truncate(target), nil)
	case "truncate-divergent":
		target = recoveryIdentifier("B", 2)
		record("Truncate", target, nil, tree.Truncate(target), nil)
	case "truncate-origin":
		target = types.ZeroHashHeight
		record("Truncate", target, nil, tree.Truncate(target), nil)
	case "truncate-origin-alias":
		target = recoveryIdentifier("X", 0)
		record("Truncate", target, nil, tree.Truncate(target), nil)
	case "prune-retained":
		target = recoveryIdentifier("A", 1)
		record("Prune:2", types.ZeroHashHeight, nil, tree.Prune(2), nil)
	case "prune-frontier":
		record("Prune:4", types.ZeroHashHeight, nil, tree.Prune(4), nil)
	case "bulk-gap":
		target = recoveryIdentifier("A", 2)
		record("Truncate", target, nil, tree.Truncate(target), nil)
	case "empty-version":
		target = recoveryIdentifier("A", 1)
	case "failed-compute-preserves-staging":
		recoveryMust(tree.Update(recoveryPatch("A", 99)))
		counter := &recoveryCounter{Patch: recoveryPatch("A", 77), fail: true}
		wrong := recoveryIdentifier("B", 2)
		root, failure := tree.ComputeRoot(wrong, counter)
		record("ComputeRoot:injected-replay", wrong, root.String(), failure, counter)
		target = recoveryIdentifier("A", 4)
		record("Commit:pending", target, nil, tree.Commit(target), nil)
	case "commit-origin-after-max":
		recoveryMust(tree.Update(recoveryPatch("A", 2)))
		record("Commit:origin", types.ZeroHashHeight, nil, tree.Commit(types.ZeroHashHeight), nil)
		target = recoveryIdentifier("A", ^uint64(0))
	default:
		panic("unselected low-level case")
	}
	after := recoveryRecords(ldb)
	frontier := tree.FrontierIdentifier()
	frontRoot, frontErr := tree.Root(frontier)
	queries := recoveryQueries(recoveryQuerySource{tree.Root, tree.Prove, tree.ComputeRoot}, target)
	recoveryMust(ldb.Close())
	reopened, err := leveldb.OpenFile(dir, nil)
	recoveryMust(err)
	reopenedRecords := recoveryRecords(reopened)
	next, openErr := trie.NewNodeTree(reopened)
	var nextFrontier, nextRoot any
	var nextRootErr any
	if openErr == nil {
		nextFrontier = recoveryID(next.FrontierIdentifier())
		root, err := next.Root(next.FrontierIdentifier())
		nextRoot, nextRootErr = root.String(), recoveryError(err)
	}
	recoveryMust(reopened.Close())
	return map[string]any{
		"name": name, "records_before": before, "operations": ops, "records_after": after,
		"frontier": recoveryID(frontier), "frontier_root": frontRoot.String(), "frontier_root_error": recoveryError(frontErr),
		"query_identifier": recoveryID(target), "queries": queries,
		"records_after_close_reopen": reopenedRecords, "reopen_error": recoveryError(openErr),
		"reopen_frontier": nextFrontier, "reopen_root": nextRoot, "reopen_root_error": nextRootErr,
	}
}

func TestCandidateHashBoundVersions(t *testing.T) {
	variant := os.Getenv("ZENON_HASH_BOUND_SUCCESSOR_VARIANT")
	if variant != "baseline" && variant != "hash-bound" {
		t.Fatal("select one explicit source variant")
	}
	handler := common.ChainLogger.GetHandler()
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	defer common.ChainLogger.SetHandler(handler)
	items := []recoveryInput{
		{Name: "empty-short", SeedFork: "A", ChainFork: "A", ChainHeight: 2, Rounds: 1},
		{Name: "empty-tail-bound", SeedFork: "A", ChainFork: "A", ChainHeight: 10, Rounds: 1},
		{Name: "empty-tail-plus-one", SeedFork: "A", ChainFork: "A", ChainHeight: 11, Rounds: 1},
		{Name: "matching-prebuild", SeedFork: "A", SeedHeight: 2, ChainFork: "A", ChainHeight: 2, Rounds: 1},
		{Name: "same-height-other-hash", SeedFork: "A", SeedHeight: 2, ChainFork: "B", ChainHeight: 2, Rounds: 1},
		{Name: "below-matching-ancestor", SeedFork: "A", SeedHeight: 1, ChainFork: "A", ChainHeight: 2, Rounds: 1},
		{Name: "below-other-ancestor", SeedFork: "X", SeedHeight: 1, ChainFork: "A", ChainHeight: 2, Rounds: 1},
		{Name: "above-matching-retained", SeedFork: "A", SeedHeight: 3, ChainFork: "A", ChainHeight: 2, Rounds: 1},
		{Name: "above-divergent-retained", SeedFork: "A", SeedHeight: 3, ChainFork: "B", ChainHeight: 2, Rounds: 1},
		{Name: "reopened-divergent-retained", SeedFork: "A", SeedHeight: 3, ChainFork: "B", ChainHeight: 2, Rounds: 2},
		{Name: "previously-ready-divergent", SeedFork: "A", SeedHeight: 3, ChainFork: "B", ChainHeight: 2, Rounds: 1, PrimeReady: true},
		{Name: "previously-ready-equal-height", SeedFork: "A", SeedHeight: 3, ChainFork: "B", ChainHeight: 3, Rounds: 1, PrimeReady: true},
		{Name: "previously-ready-behind-wrong-ancestor", SeedFork: "A", SeedHeight: 3, ChainFork: "B", ChainHeight: 4, Rounds: 1, PrimeReady: true},
		{Name: "legacy-format-2", SeedFork: "A", SeedHeight: 3, ChainFork: "A", ChainHeight: 3, Rounds: 2, Fault: "legacy-2"},
		{Name: "candidate-format-3", SeedFork: "A", SeedHeight: 3, ChainFork: "A", ChainHeight: 3, Rounds: 1, Fault: "candidate-3"},
		{Name: "foreign-format-4", SeedFork: "A", SeedHeight: 3, ChainFork: "B", ChainHeight: 3, Rounds: 1, Fault: "foreign-4"},
		{Name: "corrupt-frontier-hash", SeedFork: "A", SeedHeight: 3, ChainFork: "B", ChainHeight: 3, Rounds: 2, Fault: "frontier-hash"},
		{Name: "missing-frontier-hash", SeedFork: "A", SeedHeight: 3, ChainFork: "A", ChainHeight: 3, Rounds: 1, Fault: "missing-frontier-hash"},
		{Name: "short-frontier-hash", SeedFork: "A", SeedHeight: 3, ChainFork: "A", ChainHeight: 3, Rounds: 1, Fault: "short-frontier-hash"},
		{Name: "missing-historical-hash", SeedFork: "A", SeedHeight: 3, ChainFork: "A", ChainHeight: 3, Rounds: 1, Fault: "missing-historical-hash", QueryFork: "A", QueryHeight: 1},
		{Name: "missing-root-node", SeedFork: "A", SeedHeight: 3, ChainFork: "A", ChainHeight: 3, Rounds: 1, Fault: "missing-root-node"},
		{Name: "missing-secondary-node", SeedFork: "B", SeedHeight: 3, ChainFork: "B", ChainHeight: 3, Rounds: 1, Fault: "missing-secondary-node"},
		{Name: "missing-primary-node", SeedFork: "B", SeedHeight: 3, ChainFork: "B", ChainHeight: 3, Rounds: 1, Fault: "missing-primary-node"},
		{Name: "warm-cache-pruned-base", SeedFork: "A", SeedHeight: 3, ChainFork: "A", ChainHeight: 3, Rounds: 1, Action: "cache-prune", QueryFork: "A", QueryHeight: 1},
		{Name: "warm-cache-truncated-base", SeedFork: "A", SeedHeight: 3, ChainFork: "A", ChainHeight: 3, Rounds: 1, Action: "cache-truncate"},
		{Name: "warm-cache-closed-backend", SeedFork: "A", SeedHeight: 3, ChainFork: "A", ChainHeight: 3, Rounds: 1, Action: "cache-close"},
	}
	cases := []any{}
	for _, item := range items {
		dir := filepath.Join(t.TempDir(), "tree")
		recoverySeed(dir, item.SeedFork, item.SeedHeight)
		recoveryFault(dir, item.Fault, item.SeedFork, item.SeedHeight)
		rounds := []any{}
		for round := 1; round <= item.Rounds; round++ {
			rounds = append(rounds, recoveryRound(t, dir, item, round))
		}
		cases = append(cases, map[string]any{"input": item, "rounds": rounds})
	}
	low := []any{}
	for _, name := range []string{
		"queries", "truncate-matching", "truncate-divergent", "truncate-origin",
		"truncate-origin-alias", "prune-retained", "prune-frontier", "bulk-gap",
		"empty-version", "failed-compute-preserves-staging", "commit-origin-after-max",
	} {
		low = append(low, recoveryLowLevel(t, name))
	}
	document := map[string]any{
		"format_version": 1, "kind": "successor-node-hash-bound-version-research",
		"variant": variant, "chain_cases": cases, "low_level_cases": low,
		"source_revision": "9c71ae82fc983e16f914ae085d4034030c8ebe3b",
		"consumer_result": "REFUSED", "production_state_value_accepted": false,
		"header_authentication_executed": false,
	}
	raw, err := json.Marshal(document)
	recoveryMust(err)
	fmt.Printf("HASH_BOUND_VERSIONS=%s\n", raw)
}
