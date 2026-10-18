//go:build candidate_public_cache_forward_replay

// SPDX-License-Identifier: GPL-3.0-only
// Observe public startup with separately owned native cache frontier fixtures.
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

const canonicalRoot = "864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d"
const selectedKey = "0300000000000000000000000000000000000000000304066318c6318c6318c6"
const sourceDumpSHA = "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75"

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool) {
	if !ok {
		panic("selected public cache forward-replay contract refused")
	}
}
func errorClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, chain.ErrStateTreeNotReady):
		return "not-ready"
	case err.Error() == "The cache's state is incorrect. You can fix the problem by removing the cache database manually.":
		return "cache-frontier-identity-mismatch"
	default:
		return "other"
	}
}

// Inspect logical KV bytes only after all writers have closed. Physical LevelDB
// layout and actual power-loss durability are outside this digest's scope.
func inspectCache(root string) map[string]any {
	handle, err := leveldb.OpenFile(filepath.Join(root, "cache"), &opt.Options{ErrorIfMissing: true, ReadOnly: true,
		BlockCacheCapacity: 1 << 20, OpenFilesCacheCapacity: 16})
	must(err)
	defer func() { must(handle.Close()) }()
	raw, err := handle.Get([]byte{85, 0}, nil)
	frontier := &types.HashHeight{}
	if err == leveldb.ErrNotFound {
		require(len(raw) == 0)
	} else {
		must(err)
		require(len(raw) > 1 && len(raw) <= 128 && raw[0] == 0)
		frontier, err = types.DeserializeHashHeight(raw[1:])
		must(err)
	}
	digest := sha256.New()
	var count, keyBytes, valueBytes uint64
	var previous []byte
	iter := handle.NewIterator(nil, nil)
	for iter.Next() {
		key, value := iter.Key(), iter.Value()
		require(len(key) > 0 && len(key) <= 256 && len(value) <= 16<<20 && count < 1000000 &&
			(previous == nil || bytes.Compare(previous, key) < 0))
		must(binary.Write(digest, binary.BigEndian, uint64(len(key))))
		_, err = digest.Write(key)
		must(err)
		must(binary.Write(digest, binary.BigEndian, uint64(len(value))))
		_, err = digest.Write(value)
		must(err)
		count++
		keyBytes += uint64(len(key))
		valueBytes += uint64(len(value))
		previous = append(previous[:0], key...)
	}
	err = iter.Error()
	iter.Release()
	must(err)
	return map[string]any{"frontier": *frontier, "records": count, "key_bytes": keyBytes, "value_bytes": valueBytes,
		"frontier_raw_value": hex.EncodeToString(raw), "frontier_present": len(raw) > 0,
		"framing":          "ordered u64be key length, key bytes, u64be value length, value bytes",
		"raw_store_sha256": hex.EncodeToString(digest.Sum(nil))}
}

func main() {
	mode := flag.String("case", "", "selected bounded forward replay case")
	root := flag.String("root", "", "new owned empty case directory")
	flag.Parse()
	require(flag.NArg() == 0 && *root != "" && (*mode == "canonical-height-two-cache-clean-reopen" ||
		*mode == "canonical-height-one-cache-under-height-two-ledger" ||
		*mode == "foreign-height-one-cache-under-height-two-ledger" ||
		*mode == "empty-cache-replay-through-height-two-ledger"))
	entries, err := os.ReadDir(*root)
	must(err)
	require(len(entries) == 0)
	output := os.Stdout
	os.Stdout = os.Stderr
	log15.Root().SetHandler(log15.DiscardHandler())
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	encoder := json.NewEncoder(output)
	emit := func(stage string, fields map[string]any) {
		fields["case"], fields["stage"] = *mode, stage
		must(encoder.Encode(fields))
	}
	key, err := hex.DecodeString(selectedKey)
	must(err)
	g, err := genesis.MakeEmbeddedGenesisConfig()
	must(err)
	m := g.GetGenesisMomentum()
	raw := g.GetGenesisTransaction().Changes.Dump()
	sha := sha256.Sum256(raw)
	require(m.Hash.String() == "9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0" &&
		m.ComputeHash() == m.Hash && m.Height == 1 && m.Version == 1 && m.ChainIdentifier == 1 &&
		m.StateRoot == types.ZeroHash && len(m.PublicKey) == 0 && len(m.Signature) == 0 &&
		len(raw) == 10849399 && hex.EncodeToString(sha[:]) == sourceDumpSHA)
	a1 := m.Identifier()
	emptyPatch := db.NewPatch()
	emptyDump := append([]byte(nil), emptyPatch.Dump()...)
	emptyDigest := sha256.Sum256(emptyDump)
	next := &nom.Momentum{Version: 1, ChainIdentifier: 1, PreviousHash: a1.Hash,
		Height: 2, TimestampUnix: m.TimestampUnix + 10, ChangesHash: types.NewHash(emptyDump)}
	next.Hash = next.ComputeHash()
	a2 := next.Identifier()
	b1 := a1
	b1.Hash[0] ^= 1
	emit("source-genesis-and-unsigned-second-momentum", map[string]any{
		"genesis_identifier": a1, "genesis_timestamp": m.TimestampUnix, "second_momentum": next,
		"second_identifier": a2, "input_patch_dump": hex.EncodeToString(emptyDump),
		"input_patch_sha256":  hex.EncodeToString(emptyDigest[:]),
		"genesis_patch_bytes": len(raw), "genesis_patch_sha256": sourceDumpSHA,
		"network_started": false, "consensus_validation_selected": false, "wallet_signing_or_broadcast": false})
	treePath := filepath.Join(*root, "canonical-tree")
	makeChain := func(cacheRoot string) (chain.Chain, db.Manager) {
		manager := db.NewLevelDBManager(filepath.Join(*root, "ledger"))
		return chain.NewChain(manager, storage.NewCacheDBManager(cacheRoot), g, treePath, false), manager
	}
	cacheRoot := filepath.Join(*root, "canonical-cache")
	prime, ledger := makeChain(cacheRoot)
	must(prime.Init())
	initialRoot, err := prime.StateRoot(a1)
	must(err)
	require(initialRoot.String() == canonicalRoot && prime.StateTreeReady() &&
		prime.GetFrontierCacheStore().Identifier() == a1)
	// These are direct component calls on an unsigned local fixture. They do not
	// invoke consensus, Chain.Start, wallets, signing, RPC or a full node service.
	locker := prime.AcquireInsert("bounded unsigned local replay fixture")
	must(prime.AddMomentumTransaction(locker, &nom.MomentumTransaction{Momentum: next, Changes: emptyPatch}))
	require(prime.GetFrontierMomentumStore().Identifier() == a2 &&
		prime.GetFrontierCacheStore().Identifier() == a1)
	detailed, err := prime.GetFrontierMomentumStore().PrefetchMomentum(next)
	must(err)
	changes := ledger.GetPatch(a2)
	require(changes != nil)
	if *mode == "canonical-height-two-cache-clean-reopen" {
		must(prime.UpdateCache(locker, detailed, changes))
	}
	must(prime.UpdateStateTree(locker, detailed, changes))
	locker.Unlock()
	primedRoot, err := prime.StateRoot(a2)
	must(err)
	require(primedRoot.String() == canonicalRoot && prime.StateTreeReady())
	primedCache := a1
	if *mode == "canonical-height-two-cache-clean-reopen" {
		primedCache = a2
	}
	require(prime.GetFrontierCacheStore().Identifier() == primedCache)
	must(prime.Stop())
	emit("canonical-height-two-ledger-and-tree-primed", map[string]any{
		"identifier": a2, "root": primedRoot.String(), "cache_identifier": primedCache,
		"ready_after_stop": prime.StateTreeReady()})
	metadataOnly := *mode == "foreign-height-one-cache-under-height-two-ledger"
	empty := *mode == "empty-cache-replay-through-height-two-ledger"
	if metadataOnly || empty {
		cacheRoot = filepath.Join(*root, "controlled-cache")
		manager := storage.NewCacheDBManager(cacheRoot)
		if metadataOnly {
			// This is only native metadata with a noncanonical retained identifier.
			// It is not an independently valid alternate-chain application.
			must(manager.Add(b1, db.NewPatch()))
		}
		must(manager.Stop())
	}
	before := inspectCache(cacheRoot)
	wanted := primedCache
	if metadataOnly {
		wanted = b1
	} else if empty {
		wanted = types.ZeroHashHeight
	}
	require(before["frontier"] == wanted)
	before["metadata_only_fixture"], before["empty_cache_fixture"] = metadataOnly, empty
	emit("cache-fixture-before-public-init", before)
	c, _ := makeChain(cacheRoot)
	require(c.GetFrontierMomentumStore().Identifier() == a2)
	initErr := c.Init()
	emit("public-init-returned", map[string]any{"error": errorClass(initErr), "ready": c.StateTreeReady(),
		"ledger_frontier": c.GetFrontierMomentumStore().Identifier(),
		"cache_frontier":  c.GetFrontierCacheStore().Identifier(),
		"frontiers_equal": c.GetFrontierMomentumStore().Identifier() == c.GetFrontierCacheStore().Identifier()})
	query := func(current chain.Chain, stage string) {
		root, rootErr := current.StateRoot(a2)
		value, proof, proofErr := current.GetProof(a2, key)
		emit(stage, map[string]any{"identifier": a2, "root": root.String(), "root_error": errorClass(rootErr),
			"value": hex.EncodeToString(value), "proof": hex.EncodeToString(proof), "proof_error": errorClass(proofErr)})
	}
	query(c, "public-state-query")
	must(c.Stop())
	emit("public-stop", map[string]any{"ready": c.StateTreeReady()})
	emit("cache-fixture-after-public-stop", inspectCache(cacheRoot))
	if initErr == nil {
		reopened, _ := makeChain(cacheRoot)
		err := reopened.Init()
		emit("public-clean-reopen", map[string]any{"error": errorClass(err), "ready": reopened.StateTreeReady(),
			"ledger_frontier": reopened.GetFrontierMomentumStore().Identifier(),
			"cache_frontier":  reopened.GetFrontierCacheStore().Identifier()})
		query(reopened, "reopened-state-query")
		must(reopened.Stop())
	}
	fmt.Fprintln(os.Stderr, "PUBLIC_CACHE_FORWARD_REPLAY_PROCESS_COMPLETE")
}
