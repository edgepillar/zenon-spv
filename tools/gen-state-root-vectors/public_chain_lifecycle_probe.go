//go:build candidate_public_chain_lifecycle

// SPDX-License-Identifier: GPL-3.0-only
// Exercise public Chain lifecycle APIs on fresh owned disk databases.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"github.com/zenon-network/go-zenon/chain"
	"github.com/zenon-network/go-zenon/chain/cache/storage"
	"github.com/zenon-network/go-zenon/chain/genesis"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	mode := flag.String("case", "", "selected sequential lifecycle case")
	root := flag.String("root", "", "new caller-owned case directory")
	keyText := flag.String("key", "", "preselected covered key")
	flag.Parse()
	if (*mode != "init-after-stop" && *mode != "start-after-stop" && *mode != "stop-before-init") || *root == "" || flag.NArg() != 0 {
		panic("unselected case")
	}
	key, err := hex.DecodeString(*keyText)
	must(err)
	if len(key) != 32 || key[0] != 3 || key[21] != 3 {
		panic("unselected key domain")
	}
	entries, err := os.ReadDir(*root)
	must(err)
	if len(entries) != 0 {
		panic("fresh case root required")
	}
	output := os.Stdout
	os.Stdout = os.Stderr
	log15.Root().SetHandler(log15.DiscardHandler())
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	encoder := json.NewEncoder(output)
	emit := func(stage string, fields map[string]any) {
		fields["stage"] = stage
		fields["case"] = *mode
		must(encoder.Encode(fields))
	}
	g, err := genesis.MakeEmbeddedGenesisConfig()
	must(err)
	m := g.GetGenesisMomentum()
	raw := g.GetGenesisTransaction().Changes.Dump()
	digest := sha256.Sum256(raw)
	if m.Hash.String() != "9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0" || m.ComputeHash() != m.Hash ||
		m.Version != 1 || m.Height != 1 || m.ChainIdentifier != 1 || m.PreviousHash != types.ZeroHash ||
		m.StateRoot != types.ZeroHash || len(m.PublicKey) != 0 || len(m.Signature) != 0 ||
		len(raw) != 10849399 || hex.EncodeToString(digest[:]) != "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75" {
		panic("source genesis differs")
	}
	emit("source-genesis", map[string]any{"identifier": m.Identifier(), "raw_patch_bytes": len(raw), "raw_patch_sha256": hex.EncodeToString(digest[:]),
		"genesis_VM_derivation": true, "network_started": false, "wallet_signing_or_broadcast": false})
	makeChain := func() chain.Chain {
		manager := db.NewLevelDBManager(filepath.Join(*root, "ledger"))
		cache := storage.NewCacheDBManager(*root)
		return chain.NewChain(manager, cache, g, filepath.Join(*root, "state-tree"), false)
	}
	c := makeChain()
	defer func() { _ = c.Stop() }()
	if *mode == "stop-before-init" {
		err = c.Stop()
		emit("stopped-before-init", map[string]any{"error": errorText(err), "ready": c.StateTreeReady()})
		must(err)
	} else {
		must(c.Init())
		emit("initialized", map[string]any{"ready": c.StateTreeReady()})
		must(c.Start())
		emit("started", map[string]any{"ready": c.StateTreeReady()})
		rootHash, rootErr := c.StateRoot(m.Identifier())
		value, proof, proofErr := c.GetProof(m.Identifier(), key)
		wrong := m.Identifier()
		wrong.Hash[0] ^= 1
		_, wrongErr := c.StateRoot(wrong)
		emit("query", map[string]any{"root": rootHash.String(), "root_error": errorText(rootErr), "value": hex.EncodeToString(value),
			"proof": hex.EncodeToString(proof), "proof_error": errorText(proofErr), "wrong_hash_error": errorText(wrongErr)})
		must(rootErr)
		must(proofErr)
		must(c.Stop())
		emit("stopped", map[string]any{"ready": c.StateTreeReady()})
		// A separate object and fresh real managers must reopen the same owned data.
		reopened := makeChain()
		must(reopened.Init())
		must(reopened.Start())
		reopenedRoot, reopenedErr := reopened.StateRoot(m.Identifier())
		emit("clean-reopen", map[string]any{"ready": reopened.StateTreeReady(), "root": reopenedRoot.String(), "error": errorText(reopenedErr)})
		must(reopenedErr)
		must(reopened.Stop())
	}
	emit("terminal-call-selected", map[string]any{"call": *mode})
	if *mode == "start-after-stop" {
		err = c.Start()
	} else {
		err = c.Init()
	}
	emit("terminal-call-returned", map[string]any{"error": errorText(err), "ready": c.StateTreeReady()})
	must(c.Stop())
	emit("repeat-stop", map[string]any{"error": nil, "ready": c.StateTreeReady()})
	fmt.Fprintln(os.Stderr, "PUBLIC_CHAIN_LIFECYCLE_PROCESS_COMPLETE")
}
func errorText(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}
