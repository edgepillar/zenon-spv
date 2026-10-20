//go:build candidate_public_startup_record_identity

// SPDX-License-Identifier: GPL-3.0-only
// Observe public Chain startup against owned, deliberately altered ledger rows.
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
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/zenon-network/go-zenon/chain"
	"github.com/zenon-network/go-zenon/chain/cache/storage"
	"github.com/zenon-network/go-zenon/chain/genesis"
	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

const sourceRoot = "864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d"
const dumpSHA = "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75"

var cases = []string{
	"healthy-clean-reopen",
	"missing-genesis", "genesis-wrong-height", "genesis-body-hash-mismatch",
	"missing-frontier", "frontier-wrong-height", "frontier-wrong-hash", "frontier-body-hash-mismatch",
	"corrupt-genesis", "corrupt-frontier", "ledger-manager-stopped", "cache-manager-stopped",
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool) {
	if !ok {
		panic("public startup record observation refused")
	}
}
func sum(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }

type image struct {
	Records    uint64 `json:"records"`
	KeyBytes   uint64 `json:"key_bytes"`
	ValueBytes uint64 `json:"value_bytes"`
	SHA256     string `json:"sha256"`
}

func inspect(path string) image {
	handle, err := leveldb.OpenFile(path, &opt.Options{ErrorIfMissing: true, ReadOnly: true, BlockCacheCapacity: 1 << 20, OpenFilesCacheCapacity: 16})
	must(err)
	defer func() { must(handle.Close()) }()
	out := image{}
	digest := sha256.New()
	iter := handle.NewIterator(nil, nil)
	var previous []byte
	for iter.Next() {
		k, v := iter.Key(), iter.Value()
		require(len(k) > 0 && len(k) <= 256 && len(v) <= 16<<20 && out.Records < 1000000 && (previous == nil || bytes.Compare(previous, k) < 0))
		// Raw LevelDB iteration proves key presence. A zero-length raw value is
		// retained here, including a delete-aware layer's stored tombstone.
		must(binary.Write(digest, binary.BigEndian, uint64(len(k))))
		_, err = digest.Write(k)
		must(err)
		must(binary.Write(digest, binary.BigEndian, uint64(len(v))))
		_, err = digest.Write(v)
		must(err)
		out.Records++
		out.KeyBytes += uint64(len(k))
		out.ValueBytes += uint64(len(v))
		previous = append(previous[:0], k...)
	}
	must(iter.Error())
	iter.Release()
	out.SHA256 = hex.EncodeToString(digest.Sum(nil))
	return out
}
func images(root string) map[string]image {
	return map[string]image{"ledger": inspect(filepath.Join(root, "ledger")), "cache": inspect(filepath.Join(root, "cache")), "tree": inspect(filepath.Join(root, "tree"))}
}

type result struct {
	Class     string `json:"error_class"`
	ErrorSHA  string `json:"error_sha256"`
	Panic     bool   `json:"panic"`
	PanicType string `json:"panic_type"`
	PanicSHA  string `json:"panic_sha256"`
}

func classify(err error) string {
	if err == nil {
		return "none"
	}
	switch {
	case errors.Is(err, chain.ErrStateTreeNotReady):
		return "not-ready"
	case strings.HasPrefix(err.Error(), "can't initialize chain:"):
		return strings.SplitN(strings.TrimPrefix(err.Error(), "can't initialize chain: "), " ", 2)[0]
	default:
		return "other"
	}
}
func capture(call func() error) (out result) {
	out.Class = "none"
	defer func() {
		if v := recover(); v != nil {
			out.Class = "panic"
			out.Panic = true
			out.PanicType = fmt.Sprintf("%T", v)
			out.PanicSHA = sum([]byte(fmt.Sprint(v)))
		}
	}()
	err := call()
	out.Class = classify(err)
	if err != nil {
		out.ErrorSHA = sum([]byte(err.Error()))
	}
	return
}
func entryKey(id types.HashHeight) []byte {
	actual := db.FrontierWriteKeys(id)[2]
	expected := make([]byte, 9)
	expected[0] = 2
	binary.BigEndian.PutUint64(expected[1:], id.Height)
	require(bytes.Equal(actual, expected))
	return append([]byte{85}, actual...)
}
func header(m *nom.Momentum) map[string]any {
	raw, err := m.Serialize()
	must(err)
	content := m.Content.Hash()
	return map[string]any{"version": m.Version, "chain_identifier": m.ChainIdentifier, "hash": m.Hash.String(),
		"previous_hash": m.PreviousHash.String(), "height": m.Height, "timestamp": m.TimestampUnix,
		"data_hex": hex.EncodeToString(m.Data), "content_hash": content.String(), "changes_hash": m.ChangesHash.String(),
		"next_fusion_price": m.NextFusionPrice, "next_work_price": m.NextWorkPrice, "state_root": m.StateRoot.String(),
		"public_key_bytes": len(m.PublicKey), "signature_bytes": len(m.Signature), "serialized_bytes": len(raw), "serialized_sha256": sum(raw)}
}
func mutation(path, mode string, a1, a2 types.HashHeight) map[string]any {
	if mode == "healthy-clean-reopen" || strings.HasSuffix(mode, "manager-stopped") {
		return map[string]any{"kind": "none"}
	}
	id := a2
	if strings.Contains(mode, "genesis") {
		id = a1
	}
	key := entryKey(id)
	handle, err := leveldb.OpenFile(path, &opt.Options{ErrorIfMissing: true, BlockCacheCapacity: 1 << 20, WriteBuffer: 1 << 20, OpenFilesCacheCapacity: 16})
	must(err)
	old, err := handle.Get(key, nil)
	must(err)
	require(len(old) > 1 && old[0] == 0 && len(old) <= 1<<20)
	m, err := nom.DeserializeMomentum(old[1:])
	must(err)
	require(m.Identifier() == id && m.ComputeHash() == id.Hash)
	before := header(m)
	var after []byte
	present := true
	switch {
	case strings.HasPrefix(mode, "missing-"):
		must(handle.Delete(key, &opt.WriteOptions{Sync: true}))
		present = false
	case strings.HasPrefix(mode, "corrupt-"):
		after = []byte{0, 255}
		must(handle.Put(key, after, &opt.WriteOptions{Sync: true}))
	default:
		switch {
		case strings.HasSuffix(mode, "wrong-height"):
			m.Height++
		case strings.HasSuffix(mode, "wrong-hash"):
			m.Hash[0] ^= 1
		case strings.HasSuffix(mode, "body-hash-mismatch"):
			m.TimestampUnix++
		default:
			panic("unknown owned row mutation")
		}
		raw, e := m.Serialize()
		must(e)
		after = append([]byte{0}, raw...)
		must(handle.Put(key, after, &opt.WriteOptions{Sync: true}))
	}
	must(handle.Close())
	deltas := []map[string]any{}
	if present && len(after) == len(old) {
		for i := range old {
			if old[i] != after[i] {
				deltas = append(deltas, map[string]any{"offset": i, "before": int(old[i]), "after": int(after[i])})
			}
		}
	}
	var afterHeader any
	if present && !strings.HasPrefix(mode, "corrupt-") {
		decoded, e := nom.DeserializeMomentum(after[1:])
		must(e)
		afterHeader = header(decoded)
	}
	return map[string]any{"kind": mode, "key_hex": hex.EncodeToString(key), "selected_identifier": id, "before_header": before,
		"before_value_sha256": sum(old), "before_value_bytes": len(old), "before_presence_prefix": int(old[0]),
		"after_present": present, "after_value_sha256": sum(after), "after_value_bytes": len(after), "after_header": afterHeader,
		"same_length_byte_changes": deltas, "corrupt_after_hex": func() string {
			if strings.HasPrefix(mode, "corrupt-") {
				return hex.EncodeToString(after)
			}
			return ""
		}()}
}
func rawPresence(root string) image {
	path := filepath.Join(root, "raw-presence-control")
	handle, err := leveldb.OpenFile(path, &opt.Options{ErrorIfExist: true})
	must(err)
	must(handle.Put([]byte{17}, []byte{}, nil))
	must(handle.Put([]byte{34}, []byte("deleted"), nil))
	must(handle.Delete([]byte{34}, nil))
	must(handle.Close())
	got := inspect(path)
	frame := make([]byte, 17)
	binary.BigEndian.PutUint64(frame[:8], 1)
	frame[8] = 17
	require(got.Records == 1 && got.KeyBytes == 1 && got.ValueBytes == 0 && got.SHA256 == sum(frame))
	return got
}
func main() {
	root := flag.String("root", "", "fresh owned empty case root")
	flag.Parse()
	require(flag.NArg() == 0 && *root != "")
	entries, err := os.ReadDir(*root)
	must(err)
	require(len(entries) == 0)
	output := os.Stdout
	os.Stdout = os.Stderr
	log15.Root().SetHandler(log15.DiscardHandler())
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	enc := json.NewEncoder(output)
	emit := func(stage, caseName string, fields map[string]any) {
		fields["stage"], fields["case"] = stage, caseName
		must(enc.Encode(fields))
	}
	emit("raw-presence-control", "", map[string]any{"image": rawPresence(*root), "raw_zero_length_values_retained": true})
	g, err := genesis.MakeEmbeddedGenesisConfig()
	must(err)
	first := g.GetGenesisMomentum()
	a1 := first.Identifier()
	dump := g.GetGenesisTransaction().Changes.Dump()
	require(a1.Hash.String() == "9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0" && a1.Height == 1 && first.ComputeHash() == a1.Hash && first.Version == 1 && first.ChainIdentifier == 1 && len(first.PublicKey) == 0 && len(first.Signature) == 0 && len(dump) == 10849399 && sum(dump) == dumpSHA)
	second := &nom.Momentum{Version: 1, ChainIdentifier: 1, PreviousHash: a1.Hash, Height: 2, TimestampUnix: first.TimestampUnix + 10, ChangesHash: types.NewHash(nil)}
	second.Hash = second.ComputeHash()
	a2 := second.Identifier()
	require(a2.Hash.String() == "fbe4d2002715d5993894e36fe23eefab052ffe697861465b1be8c07d786beed0")
	emit("source-selection", "", map[string]any{"genesis": header(first), "second": header(second), "genesis_patch_bytes": len(dump), "genesis_patch_sha256": dumpSHA, "cases": cases,
		"chain_start_called": false, "full_node_or_network_started": false, "wallet_signing_or_broadcast": false, "consumer_result": "REFUSED"})
	for _, mode := range cases {
		g, err := genesis.MakeEmbeddedGenesisConfig()
		must(err)
		require(g.GetGenesisMomentum().Identifier() == a1 && sum(g.GetGenesisTransaction().Changes.Dump()) == dumpSHA)
		dir := filepath.Join(*root, mode)
		must(os.Mkdir(dir, 0700))
		ledger := db.NewLevelDBManager(filepath.Join(dir, "ledger"))
		pool := chain.NewMomentumPool(ledger, g)
		locker := &sync.Mutex{}
		tx := *g.GetGenesisTransaction()
		tx.Changes, err = db.NewPatchFromDump(dump)
		must(err)
		locker.Lock()
		err = pool.AddMomentumTransaction(locker, &tx)
		locker.Unlock()
		must(err)
		locker.Lock()
		err = pool.AddMomentumTransaction(locker, &nom.MomentumTransaction{Momentum: second, Changes: db.NewPatch()})
		locker.Unlock()
		must(err)
		must(ledger.Stop())
		open := func() (chain.Chain, db.Manager, storage.CacheManager) {
			lm := db.NewLevelDBManager(filepath.Join(dir, "ledger"))
			cm := storage.NewCacheDBManager(dir)
			return chain.NewChain(lm, cm, g, filepath.Join(dir, "tree"), false), lm, cm
		}
		prime, _, _ := open()
		must(prime.Init())
		r, err := prime.StateRoot(a2)
		must(err)
		require(prime.StateTreeReady() && r.String() == sourceRoot)
		must(prime.Stop())
		seeded := images(dir)
		emit("fixture-seeded", mode, map[string]any{"images": seeded, "frontier": a2, "source_projection_root": r.String()})
		changed := mutation(filepath.Join(dir, "ledger"), mode, a1, a2)
		before := images(dir)
		emit("fixture-before-public-init", mode, map[string]any{"images": before, "mutation": changed, "ledger_frontier_metadata": a2})
		c, lm, cm := open()
		if mode == "ledger-manager-stopped" {
			must(lm.Stop())
		}
		if mode == "cache-manager-stopped" {
			must(cm.Stop())
		}
		got := capture(c.Init)
		ready := c.StateTreeReady()
		r, rootErr := c.StateRoot(a2)
		emit("public-init-observation", mode, map[string]any{"result": got, "state_tree_ready": ready, "root_query_result": capture(func() error { return rootErr }), "root": r.String()})
		stopped := capture(c.Stop)
		require(stopped.Class == "none" && !stopped.Panic && !c.StateTreeReady())
		emit("public-stop-observation", mode, map[string]any{"result": stopped, "state_tree_ready": c.StateTreeReady()})
		after := images(dir)
		require(before["ledger"] == after["ledger"] && before["cache"] == after["cache"] && before["tree"] == after["tree"])
		emit("fixture-after-public-stop", mode, map[string]any{"images": after, "raw_images_unchanged": true})
		if mode == "healthy-clean-reopen" {
			reopened, _, _ := open()
			must(reopened.Init())
			r, err = reopened.StateRoot(a2)
			must(err)
			require(reopened.StateTreeReady() && r.String() == sourceRoot)
			must(reopened.Stop())
			final := images(dir)
			require(final["ledger"] == before["ledger"] && final["cache"] == before["cache"] && final["tree"] == before["tree"])
			emit("public-clean-reopen", mode, map[string]any{"images": final, "root": r.String(), "state_tree_ready_after_stop": reopened.StateTreeReady()})
		}
		changes := g.GetGenesisTransaction().Changes
		fields := map[string]any{"changes_present": changes != nil, "bytes": 0, "sha256": sum(nil)}
		if changes != nil {
			raw := changes.Dump()
			fields["bytes"] = len(raw)
			fields["sha256"] = sum(raw)
			require(sum(raw) == dumpSHA)
		}
		emit("configured-genesis-transaction-after-stop", mode, fields)
	}
	fmt.Fprintln(os.Stderr, "PUBLIC_STARTUP_RECORD_PROCESS_COMPLETE")
}
