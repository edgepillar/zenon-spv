//go:build candidate_public_chain_foreign_startup

// SPDX-License-Identifier: GPL-3.0-only
// Public Chain startup against separately owned, native-format foreign trees.
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
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
)

const canonicalRoot = "864dbad1c3ef38e2c867950390364878c58238183d01b8bf97ef73e2efa4383d"
const selectedKey = "0300000000000000000000000000000000000000000304066318c6318c6318c6"
const sourceDumpSHA = "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75"
const foreignSingleLeafRoot = "29e6754c2098f405b067f62f92bc48a22ea23b45c1a7b9cc05556ed03dc385c7"
const foreignFullProjectionRoot = "7f5f225685590ad9dfc37c8caaa9f32bfd27b0a77a6d5fbb3fea2b749a47686a"

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool) {
	if !ok {
		panic("selected public Chain foreign-startup contract refused")
	}
}
func errorClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, chain.ErrStateTreeNotReady):
		return "not-ready"
	case errors.Is(err, trie.ErrVersionIdentityMismatch):
		return "version-hash-mismatch"
	case errors.Is(err, trie.ErrVersionIdentityMissing):
		return "version-hash-missing"
	case errors.Is(err, trie.ErrNoVersion):
		return "no-version"
	case errors.Is(err, trie.ErrCorrupt):
		return "corrupt"
	case err.Error() == "the state tree's state is incorrect. You can fix the problem by removing the state-tree database manually.":
		return "chain-frontier-identity-mismatch"
	default:
		return "other"
	}
}

// Hash a framed ordered raw-store manifest without retaining another DB copy.
// These are closed-handle inspection phases, not a whole-pipeline peak budget.
func inspectTree(path string, key []byte, ids []types.HashHeight) map[string]any {
	handle, err := leveldb.OpenFile(path, &opt.Options{ErrorIfMissing: true, ReadOnly: true,
		BlockCacheCapacity: 1 << 20, OpenFilesCacheCapacity: 16})
	must(err)
	defer func() { must(handle.Close()) }()
	tree, err := trie.NewNodeTree(handle)
	must(err)
	digest := sha256.New()
	var count, keyBytes, valueBytes uint64
	var previous []byte
	iter := handle.NewIterator(nil, nil)
	for iter.Next() {
		k, v := iter.Key(), iter.Value()
		require(len(k) > 0 && len(k) <= 128 && len(v) <= 1<<20 && count < 1000000 &&
			(previous == nil || bytes.Compare(previous, k) < 0))
		must(binary.Write(digest, binary.BigEndian, uint64(len(k))))
		_, err = digest.Write(k)
		must(err)
		must(binary.Write(digest, binary.BigEndian, uint64(len(v))))
		_, err = digest.Write(v)
		must(err)
		count++
		keyBytes += uint64(len(k))
		valueBytes += uint64(len(v))
		previous = append(previous[:0], k...)
	}
	err = iter.Error()
	iter.Release()
	must(err)
	queries := []map[string]any{}
	for _, id := range ids {
		root, err := tree.Root(id)
		queries = append(queries, map[string]any{"identifier": id, "root": root.String(), "error": errorClass(err)})
	}
	return map[string]any{"frontier": tree.FrontierIdentifier(), "roots": queries,
		"records": count, "key_bytes": keyBytes, "value_bytes": valueBytes,
		"framing":          "ordered u64be key length, key bytes, u64be value length, value bytes",
		"raw_store_sha256": hex.EncodeToString(digest.Sum(nil))}
}

func main() {
	mode := flag.String("case", "", "selected ordinary public startup case")
	root := flag.String("root", "", "new owned empty case directory")
	flag.Parse()
	require(flag.NArg() == 0 && *root != "" && (*mode == "canonical-source-genesis-clean-reopen" ||
		*mode == "foreign-same-height-frontier-identity" ||
		*mode == "foreign-ahead-frontier-without-canonical-retained-version" ||
		*mode == "canonical-retained-genesis-under-foreign-ahead-frontier"))
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
		m.ComputeHash() == m.Hash && m.Version == 1 && m.Height == 1 && m.ChainIdentifier == 1 &&
		m.StateRoot == types.ZeroHash && len(m.PublicKey) == 0 && len(m.Signature) == 0 &&
		len(raw) == 10849399 && hex.EncodeToString(sha[:]) == sourceDumpSHA)
	a := m.Identifier()
	b := a
	b.Hash[0] ^= 1
	b2 := b
	b2.Hash[0] ^= 2
	b2.Height = 2
	ids := []types.HashHeight{a, b, b2}
	emit("source-genesis", map[string]any{"identifier": a, "raw_patch_sha256": sourceDumpSHA,
		"raw_patch_bytes": len(raw), "network_started": false, "wallet_signing_or_broadcast": false})
	makeChain := func(treePath string) chain.Chain {
		return chain.NewChain(db.NewLevelDBManager(filepath.Join(*root, "ledger")),
			storage.NewCacheDBManager(*root), g, treePath, false)
	}
	primePath := filepath.Join(*root, "canonical-tree")
	prime := makeChain(primePath)
	must(prime.Init())
	primeRoot, err := prime.StateRoot(a)
	must(err)
	require(prime.StateTreeReady() && primeRoot.String() == canonicalRoot)
	must(prime.Stop())
	emit("canonical-ledger-primed", map[string]any{"root": primeRoot.String(), "ready_after_stop": prime.StateTreeReady()})
	treePath := primePath
	if *mode != "canonical-source-genesis-clean-reopen" {
		treePath = filepath.Join(*root, "foreign-tree")
		handle, err := leveldb.OpenFile(treePath, &opt.Options{ErrorIfExist: true,
			BlockCacheCapacity: 1 << 20, WriteBuffer: 1 << 20, OpenFilesCacheCapacity: 16})
		must(err)
		tree, err := trie.NewNodeTree(handle)
		must(err)
		change := db.NewPatch()
		value := make([]byte, 32)
		binary.BigEndian.PutUint64(value[24:], 100001)
		change.Put(key, value)
		if *mode == "canonical-retained-genesis-under-foreign-ahead-frontier" {
			initial, err := db.NewPatchFromDump(raw)
			must(err)
			must(tree.Update(initial))
			must(tree.Commit(a))
			initialRoot, err := tree.Root(a)
			must(err)
			require(initialRoot.String() == canonicalRoot)
			must(tree.Update(change))
			must(tree.Commit(b2))
		} else {
			must(tree.Update(change))
			must(tree.Commit(b))
			if *mode == "foreign-ahead-frontier-without-canonical-retained-version" {
				must(tree.Update(change))
				must(tree.Commit(b2))
			}
		}
		must(handle.Close())
	}
	before := inspectTree(treePath, key, ids)
	rootRows := before["roots"].([]map[string]any)
	switch *mode {
	case "canonical-source-genesis-clean-reopen":
		require(before["frontier"] == a && rootRows[0]["root"] == canonicalRoot && rootRows[0]["error"] == "none")
	case "foreign-same-height-frontier-identity":
		require(before["frontier"] == b && rootRows[0]["error"] == "version-hash-mismatch" &&
			rootRows[1]["root"] == foreignSingleLeafRoot && rootRows[1]["error"] == "none")
	case "foreign-ahead-frontier-without-canonical-retained-version":
		require(before["frontier"] == b2 && rootRows[0]["error"] == "version-hash-mismatch" &&
			rootRows[1]["root"] == foreignSingleLeafRoot && rootRows[2]["root"] == foreignSingleLeafRoot)
	case "canonical-retained-genesis-under-foreign-ahead-frontier":
		require(before["frontier"] == b2 && rootRows[0]["root"] == canonicalRoot && rootRows[0]["error"] == "none" &&
			rootRows[2]["root"] == foreignFullProjectionRoot && rootRows[2]["error"] == "none")
	}
	emit("fixture-before-public-init", before)
	c := makeChain(treePath)
	require(c.GetFrontierMomentumStore() != nil && c.GetFrontierMomentumStore().Identifier() == a)
	initErr := c.Init()
	emit("public-init-returned", map[string]any{"error": errorClass(initErr), "ready": c.StateTreeReady()})
	for _, id := range ids {
		r, rootErr := c.StateRoot(id)
		value, proof, proofErr := c.GetProof(id, key)
		emit("public-query", map[string]any{"identifier": id, "root": r.String(), "root_error": errorClass(rootErr),
			"value": hex.EncodeToString(value), "proof": hex.EncodeToString(proof), "proof_error": errorClass(proofErr)})
	}
	must(c.Stop())
	emit("public-stop", map[string]any{"ready": c.StateTreeReady()})
	emit("fixture-after-public-stop", inspectTree(treePath, key, ids))
	if initErr == nil {
		reopened := makeChain(treePath)
		must(reopened.Init())
		r, err := reopened.StateRoot(a)
		must(err)
		emit("public-clean-reopen", map[string]any{"root": r.String(), "ready": reopened.StateTreeReady()})
		must(reopened.Stop())
	}
	fmt.Fprintln(os.Stderr, "PUBLIC_CHAIN_FOREIGN_STARTUP_PROCESS_COMPLETE")
}
