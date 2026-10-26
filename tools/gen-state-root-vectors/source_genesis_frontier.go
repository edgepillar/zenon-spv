//go:build candidate_source_genesis_frontier

// SPDX-License-Identifier: GPL-3.0-only
// Capture an independent logical frontier from unchanged source-genesis managers.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/inconshreveable/log15"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/zenon-network/go-zenon/chain"
	"github.com/zenon-network/go-zenon/chain/cache/storage"
	"github.com/zenon-network/go-zenon/chain/genesis"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

const (
	frontierFormat = "source-genesis-node-frontier/v1"
	nodeRevision   = "9c71ae82fc983e16f914ae085d4034030c8ebe3b"
	nodeTree       = "d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6"
	genesisHash    = "9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0"
	genesisPatch   = "a222aac55304b1a489d395235c61af4182ac08b887d24d0c3f654aa402f35e75"
	maxWireBytes   = uint64(64 << 20)
	maxRecords     = uint64(2_000_000)
	maxKeyBytes    = 1024
	maxValueBytes  = 1 << 20
)

type frontierCounts struct {
	Records       uint64 `json:"records"`
	WireBytes     uint64 `json:"wire_bytes"`
	SHA256        string `json:"sha256"`
	TypedBalances uint64 `json:"typed_balance_records"`
	EmptyBalances uint64 `json:"typed_balance_present_empty"`
	ZeroBalances  uint64 `json:"typed_balance_raw_zero32"`
	WideBalances  uint64 `json:"typed_balance_values_over_32_bytes"`
}

func digest(raw []byte) string {
	value := sha256.Sum256(raw)
	return hex.EncodeToString(value[:])
}

func emptyPhysicalRoot(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) == 0
}

func logicalFrontier(view db.DB) (frontierCounts, error) {
	var result frontierCounts
	if view == nil {
		return result, errors.New("frontier unavailable")
	}
	iterator := view.NewIterator(nil)
	defer iterator.Release()
	stream := sha256.New()
	var previous []byte
	var batch leveldb.Batch
	zero := make([]byte, 32)
	for iterator.Next() {
		key, value := iterator.Key(), iterator.Value()
		if len(key) > maxKeyBytes || len(value) > maxValueBytes ||
			(result.Records != 0 && bytes.Compare(previous, key) >= 0) || result.Records >= maxRecords {
			return frontierCounts{}, errors.New("frontier bound or ordering")
		}
		// The node library's batch encoder is independent of the exporter's encoder.
		// Hash each final logical record without retaining another payload stream.
		batch.Reset()
		batch.Put(key, value)
		wire := batch.Dump()
		if uint64(len(wire)) > maxWireBytes-result.WireBytes {
			return frontierCounts{}, errors.New("frontier byte bound")
		}
		if _, err := stream.Write(wire); err != nil {
			return frontierCounts{}, errors.New("frontier hash")
		}
		result.Records++
		result.WireBytes += uint64(len(wire))
		if len(key) == 32 && key[0] == 3 && key[21] == 3 {
			result.TypedBalances++
			if len(value) == 0 {
				result.EmptyBalances++
			}
			if len(value) == 32 && bytes.Equal(value, zero) {
				result.ZeroBalances++
			}
			if len(value) > 32 {
				result.WideBalances++
			}
		}
		previous = append(previous[:0], key...)
	}
	if iterator.Error() != nil || result.Records == 0 {
		return frontierCounts{}, errors.New("frontier incomplete")
	}
	result.SHA256 = hex.EncodeToString(stream.Sum(nil))
	return result, nil
}

func capture(args []string, output, diagnostic io.Writer) (code int) {
	phase := "options"
	unknown := func() {
		_ = json.NewEncoder(diagnostic).Encode(map[string]any{
			"format": frontierFormat, "status": "UNKNOWN", "phase": phase,
			"production_state_value_accepted": false,
		})
	}
	defer func() {
		if recover() != nil {
			unknown()
			code = 1
		}
	}()
	flags := flag.NewFlagSet("source-genesis-frontier", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "existing empty physical owned control directory")
	if err := flags.Parse(args); err != nil {
		unknown()
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 64
	}
	if flags.NArg() != 0 || !emptyPhysicalRoot(*root) {
		unknown()
		return 64
	}
	log15.Root().SetHandler(log15.DiscardHandler())
	phase = "source-genesis"
	g, err := genesis.MakeEmbeddedGenesisConfig()
	if err != nil {
		unknown()
		return 1
	}
	first := g.GetGenesisMomentum()
	patch := g.GetGenesisTransaction().Changes.Dump()
	if first.Height != 1 || first.Hash.String() != genesisHash || first.Hash != first.ComputeHash() ||
		first.Version != 1 || first.StateRoot != types.ZeroHash || len(first.PublicKey) != 0 || len(first.Signature) != 0 ||
		len(patch) != 10849399 || digest(patch) != genesisPatch {
		unknown()
		return 1
	}
	phase = "manager-construction"
	ledger := db.NewLevelDBManager(filepath.Join(*root, "ledger"))
	cache := storage.NewCacheDBManager(*root)
	c := chain.NewChain(ledger, cache, g, filepath.Join(*root, "tree"), false)
	stopAttempted := false
	defer func() {
		if !stopAttempted {
			stopAttempted = true
			_ = c.Stop()
		}
	}()
	phase = "Init"
	if c.Init() != nil {
		unknown()
		return 1
	}
	phase = "frontier"
	view := ledger.Frontier()
	if view == nil || db.GetFrontierIdentifier(view) != first.Identifier() ||
		c.GetFrontierMomentumStore().Identifier() != first.Identifier() {
		unknown()
		return 1
	}
	observed, err := logicalFrontier(view)
	if err != nil || db.GetFrontierIdentifier(view) != first.Identifier() {
		unknown()
		return 1
	}
	phase = "Stop"
	stopAttempted = true
	if c.Stop() != nil || ledger.Frontier() != nil {
		unknown()
		return 1
	}
	phase = "receipt"
	if err := json.NewEncoder(output).Encode(map[string]any{
		"format": frontierFormat, "status": "SOURCE_GENESIS_FRONTIER_CLOSED",
		"declared_node_revision": nodeRevision, "declared_node_tree": nodeTree,
		"source_and_actual_exit_binding_requires_controller": true,
		"genesis": first.Identifier(), "genesis_patch_bytes": len(patch), "genesis_patch_sha256": genesisPatch,
		"logical_frontier": observed,
		"limits": map[string]uint64{"wire_bytes": maxWireBytes, "records": maxRecords,
			"key_bytes": maxKeyBytes, "value_bytes": maxValueBytes},
		"runtime":           map[string]string{"go": runtime.Version(), "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH},
		"iterator_released": true, "manager_Stop_returned_nil": true,
		"Chain_Init_selected": true, "Chain_Start_selected": false,
		"node_P2P_RPC_wallet_signing_broadcast_selected": false,
		"representative_R1_dataset":                      false, "accepted_header_binding": false,
		"production_state_value_accepted": false,
	}); err != nil {
		unknown()
		return 1
	}
	return 0
}

func main() {
	os.Exit(capture(os.Args[1:], os.Stdout, os.Stderr))
}
