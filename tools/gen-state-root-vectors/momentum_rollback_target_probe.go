//go:build candidate_momentum_rollback_target

// SPDX-License-Identifier: GPL-3.0-only
// Observe bounded rollback targets through a real disk-backed MomentumPool.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/inconshreveable/log15"
	"github.com/zenon-network/go-zenon/chain"
	"github.com/zenon-network/go-zenon/chain/genesis"
	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool) {
	if !ok {
		panic("bounded momentum rollback observation refused")
	}
}

type image struct {
	Identifier types.HashHeight `json:"identifier"`
	Records    uint64           `json:"records"`
	KeyBytes   uint64           `json:"key_bytes"`
	ValueBytes uint64           `json:"value_bytes"`
	SHA256     string           `json:"sha256"`
}

func logical(manager db.Manager) image {
	view := manager.Frontier()
	require(view != nil)
	result := image{Identifier: db.GetFrontierIdentifier(view)}
	digest := sha256.New()
	it := view.NewIterator(nil)
	defer it.Release()
	var previous []byte
	for it.Next() {
		key, value := it.Key(), it.Value()
		// The delete-aware iterator exposes nil deletion markers. A non-nil
		// zero-length value remains a present value and must be retained.
		if value == nil {
			continue
		}
		require(len(key) > 0 && len(key) <= 256 && len(value) <= 16<<20 && result.Records < 1000000 &&
			(previous == nil || bytes.Compare(previous, key) < 0))
		must(binary.Write(digest, binary.BigEndian, uint64(len(key))))
		_, err := digest.Write(key)
		must(err)
		must(binary.Write(digest, binary.BigEndian, uint64(len(value))))
		_, err = digest.Write(value)
		must(err)
		result.Records++
		result.KeyBytes += uint64(len(key))
		result.ValueBytes += uint64(len(value))
		previous = append(previous[:0], key...)
	}
	must(it.Error())
	result.SHA256 = hex.EncodeToString(digest.Sum(nil))
	return result
}

func logicalPresenceControl() image {
	store := db.NewMemDB()
	must(store.Put([]byte{0x11}, []byte{}))
	must(store.Put([]byte{0x22}, []byte("removed")))
	must(store.Delete([]byte{0x22}))
	manager := db.NewMemDBManager(store)
	empty, err := manager.Frontier().Get([]byte{0x11})
	must(err)
	require(empty != nil && len(empty) == 0)
	present, err := manager.Frontier().Has([]byte{0x22})
	must(err)
	require(!present)
	got := logical(manager)
	digest := sha256.New()
	must(binary.Write(digest, binary.BigEndian, uint64(1)))
	_, err = digest.Write([]byte{0x11})
	must(err)
	must(binary.Write(digest, binary.BigEndian, uint64(0)))
	require(got.Records == 1 && got.KeyBytes == 1 && got.ValueBytes == 0 &&
		got.SHA256 == hex.EncodeToString(digest.Sum(nil)))
	must(manager.Stop())
	return got
}

type counter struct {
	Inserts []types.HashHeight
	Deletes []types.HashHeight
}

func (c *counter) InsertMomentum(m *nom.DetailedMomentum) {
	c.Inserts = append(c.Inserts, m.Momentum.Identifier())
}
func (c *counter) DeleteMomentum(m *nom.DetailedMomentum) {
	c.Deletes = append(c.Deletes, m.Momentum.Identifier())
}

type rollbacker interface {
	RollbackTo(sync.Locker, types.HashHeight) error
}
type observation struct {
	ErrorClass              string `json:"error_class"`
	Panic                   bool   `json:"panic"`
	PanicType               string `json:"panic_type"`
	PanicText               string `json:"panic_text"`
	CanonicalStateUncertain bool   `json:"canonical_state_uncertain"`
}

func invoke(pool rollbacker, locker sync.Locker, target types.HashHeight) (out observation) {
	out.ErrorClass = "none"
	defer func() {
		if value := recover(); value != nil {
			out.Panic = true
			out.PanicType = fmt.Sprintf("%T", value)
			out.PanicText = fmt.Sprint(value)
			out.ErrorClass = "panic"
		}
	}()
	err := pool.RollbackTo(locker, target)
	switch {
	case err == nil:
	case err.Error() == "insertLocker can't be nil":
		out.ErrorClass = "nil-locker"
	case strings.HasPrefix(err.Error(), "can't rollback momentums. No momentum at height "):
		out.ErrorClass = "missing-target"
	case strings.HasPrefix(err.Error(), "can't rollback momentums. Expected "):
		out.ErrorClass = "target-identifier-mismatch"
	default:
		out.ErrorClass = "other"
	}
	var uncertain *chain.ErrCanonicalStateUncertain
	out.CanonicalStateUncertain = errors.As(err, &uncertain)
	return
}

func main() {
	root := flag.String("root", "", "new empty owned case directory")
	flag.Parse()
	require(flag.NArg() == 0 && *root != "")
	entries, err := os.ReadDir(*root)
	must(err)
	require(len(entries) == 0)
	output := os.Stdout
	os.Stdout = os.Stderr
	log15.Root().SetHandler(log15.DiscardHandler())
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	encoder := json.NewEncoder(output)
	emit := func(stage string, fields map[string]any) { fields["stage"] = stage; must(encoder.Encode(fields)) }
	emit("logical-presence-control", map[string]any{"image": logicalPresenceControl(), "present_empty_retained": true, "nil_deletion_marker_omitted": true})
	g, err := genesis.MakeEmbeddedGenesisConfig()
	must(err)
	first := g.GetGenesisMomentum()
	dump := g.GetGenesisTransaction().Changes.Dump()
	sum := sha256.Sum256(dump)
	require(first.Height == 1 && first.Version == 1 && first.ChainIdentifier == 1 &&
		first.Hash.String() == "9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0" &&
		first.Hash == first.ComputeHash() && len(first.Signature) == 0 && len(first.PublicKey) == 0 &&
		len(dump) == 10849399 && hex.EncodeToString(sum[:]) == "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75")
	a1 := first.Identifier()
	patch := db.NewPatch()
	emptyDump := append([]byte(nil), patch.Dump()...)
	second := &nom.Momentum{Version: 1, ChainIdentifier: 1, PreviousHash: a1.Hash, Height: 2,
		TimestampUnix: first.TimestampUnix + 10, ChangesHash: types.NewHash(emptyDump)}
	second.Hash = second.ComputeHash()
	a2 := second.Identifier()
	require(len(emptyDump) == 0 && second.Hash.String() == "fbe4d2002715d5993894e36fe23eefab052ffe697861465b1be8c07d786beed0")
	emit("source-selection", map[string]any{"genesis_identifier": a1, "genesis_patch_bytes": len(dump),
		"genesis_patch_sha256": hex.EncodeToString(sum[:]), "unsigned_second_momentum": second,
		"chain_init_or_start_selected": false, "cache_or_state_tree_selected": false, "network_started": false,
		"wallet_signing_or_broadcast": false, "consumer_result": "REFUSED"})
	ledgerPath := filepath.Join(*root, "ledger")
	manager := db.NewLevelDBManager(ledgerPath)
	pool := chain.NewMomentumPool(manager, g)
	locker := &sync.Mutex{}
	locker.Lock()
	err = pool.AddMomentumTransaction(locker, g.GetGenesisTransaction())
	locker.Unlock()
	must(err)
	initial := logical(manager)
	require(initial.Identifier == a1)
	emit("source-genesis-committed", map[string]any{"image": initial})
	locker.Lock()
	err = pool.AddMomentumTransaction(locker, &nom.MomentumTransaction{Momentum: second, Changes: patch})
	locker.Unlock()
	must(err)
	before := logical(manager)
	require(before.Identifier == a2)
	emit("unsigned-second-momentum-committed", map[string]any{"image": before})
	calls := new(counter)
	pool.Register(calls)
	foreign := a2
	foreign.Hash[0] ^= 1
	cases := []struct {
		name      string
		target    types.HashHeight
		nilLocker bool
	}{
		{"nil-locker", a2, true},
		{"missing-height-zero", types.ZeroHashHeight, false},
		{"missing-above-frontier", types.HashHeight{Height: 3}, false},
		{"missing-maximum-height", types.HashHeight{Height: ^uint64(0)}, false},
		{"wrong-hash-at-frontier", foreign, false},
		{"matching-frontier-noop", a2, false},
	}
	for _, selected := range cases {
		prior := logical(manager)
		var result observation
		if selected.nilLocker {
			result = invoke(pool, nil, selected.target)
		} else {
			locker.Lock()
			result = invoke(pool, locker, selected.target)
			locker.Unlock()
		}
		after := logical(manager)
		require(prior == before && after == prior && len(calls.Inserts) == 0 && len(calls.Deletes) == 0)
		emit("rollback-target-observation", map[string]any{"case": selected.name, "target": selected.target,
			"result": result, "before": prior, "after": after, "insert_callbacks": len(calls.Inserts), "delete_callbacks": len(calls.Deletes)})
	}
	locker.Lock()
	result := invoke(pool, locker, a1)
	locker.Unlock()
	after := logical(manager)
	emit("valid-one-step-rollback", map[string]any{"target": a1, "result": result, "before": before, "after": after,
		"insert_callbacks": len(calls.Inserts), "deleted_identifiers": calls.Deletes})
	require(!result.Panic && result.ErrorClass == "none" && after == initial &&
		len(calls.Inserts) == 0 && len(calls.Deletes) == 1 && calls.Deletes[0] == a2)
	locker.Lock()
	stale := invoke(pool, locker, a2)
	locker.Unlock()
	require(logical(manager) == initial && len(calls.Deletes) == 1)
	emit("removed-height-target-observation", map[string]any{"target": a2, "result": stale, "after": logical(manager),
		"insert_callbacks": len(calls.Inserts), "delete_callbacks": len(calls.Deletes)})
	must(manager.Stop())
	reopened := db.NewLevelDBManager(ledgerPath)
	restored := logical(reopened)
	require(restored == initial)
	reopenedPool := chain.NewMomentumPool(reopened, g)
	require(reopenedPool.GetFrontierMomentumStore().Identifier() == a1)
	absent, err := reopenedPool.GetFrontierMomentumStore().GetMomentumByHeight(2)
	must(err)
	require(absent == nil)
	emit("closed-manager-reopen", map[string]any{"image": restored, "removed_height_absent": true})
	must(reopened.Stop())
	fmt.Fprintln(os.Stderr, "MOMENTUM_ROLLBACK_TARGET_PROCESS_COMPLETE")
}
