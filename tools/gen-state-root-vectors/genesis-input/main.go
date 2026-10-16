// SPDX-License-Identifier: GPL-3.0-only
// Reconstruct the pinned unsigned genesis input; no NodeTree or service starts.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/zenon-network/go-zenon/chain/genesis"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/types"
)

type counter struct{ Puts, Deletes, KeyBytes, ValueBytes, BalancePuts, StoragePuts int }

func (c *counter) Put(key, value []byte) {
	c.Puts++
	c.KeyBytes += len(key)
	c.ValueBytes += len(value)
	if c.Puts+c.Deletes > 1000000 {
		panic("genesis event limit exceeded")
	}
	if len(key) >= 22 && key[0] == 3 {
		if key[21] == 3 {
			c.BalancePuts++
		}
		if key[21] == 4 {
			c.StoragePuts++
		}
	}
}
func (c *counter) Delete(key []byte) {
	c.Deletes++
	c.KeyBytes += len(key)
	if c.Puts+c.Deletes > 1000000 {
		panic("genesis event limit exceeded")
	}
}
func main() {
	output := os.Stdout
	os.Stdout = os.Stderr
	log15.Root().SetHandler(log15.DiscardHandler())
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	started := time.Now()
	g, err := genesis.MakeEmbeddedGenesisConfig()
	if err != nil {
		panic(err)
	}
	tx := g.GetGenesisTransaction()
	m := tx.Momentum
	if m.Version != 1 || m.Height != 1 || m.PreviousHash != types.ZeroHash ||
		m.StateRoot != types.ZeroHash || len(m.PublicKey) != 0 || len(m.Signature) != 0 ||
		m.ComputeHash() != m.Hash || m.ChainIdentifier != g.ChainIdentifier() {
		panic("unexpected unsigned source genesis envelope")
	}
	raw := tx.Changes.Dump()
	if len(raw) == 0 || len(raw) > 32<<20 {
		panic("genesis dump limit exceeded")
	}
	counts := new(counter)
	if err := tx.Changes.Replay(counts); err != nil {
		panic(err)
	}
	digest := sha256.Sum256(raw)
	written, err := output.Write(raw)
	if err != nil || written != len(raw) {
		panic("incomplete genesis input output")
	}
	metadata := map[string]any{
		"kind":          "pinned-source-unsigned-genesis-input",
		"node_revision": "33d7d1ee1b6a915c40aea196e2a10f1e893d171f",
		"node_tree":     "40d71efb7e462d5bbd0f27d83ed7588e121c3cb6",
		"Go_version":    runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH,
		"genesis_momentum_hash": m.Hash.String(), "version": m.Version,
		"height": m.Height, "chain_identifier": m.ChainIdentifier,
		"raw_input_sha256": hex.EncodeToString(digest[:]), "raw_input_bytes": len(raw),
		"stdout_written_bytes": written, "replay_counts": counts,
		"construction_elapsed_ns":         time.Since(started).Nanoseconds(),
		"in_memory_genesis_VM_derivation": true,
		"NodeTree_executed":               false, "chain_Init_or_Start_executed": false,
		"disk_database_opened": false, "network_executed": false,
		"signing_or_broadcast_executed": false, "production_acceptance": false,
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "GENESIS_INPUT_META=%s\n", encoded)
}
