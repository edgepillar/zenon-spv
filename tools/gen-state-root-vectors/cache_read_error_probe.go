//go:build candidate_cache_read_error

// SPDX-License-Identifier: GPL-3.0-only
// Record finite, unsigned cache-component reads on one owned real database.
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
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/zenon-network/go-zenon/chain/cache"
	"github.com/zenon-network/go-zenon/chain/cache/storage"
	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/chain/store"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

type fixture struct {
	Schema           string `json:"schema"`
	OriginalRevision string `json:"original_revision"`
	ParentRuntime    string `json:"parent_runtime_tree"`
	Subject          string `json:"subject"`
	Absent           string `json:"absent"`
	PlasmaContract   string `json:"plasma_contract"`
	MomentumHash     string `json:"momentum_hash"`
	MomentumHeight   uint64 `json:"momentum_height"`
	Spork            string `json:"unconfigured_spork_id"`
	PlasmaKey        string `json:"plasma_input_key"`
	FusedKey         string `json:"fused_input_key"`
	PlasmaValue      string `json:"plasma_input_value"`
	FusedValue       string `json:"fused_input_value"`
	InputPatch       string `json:"input_patch_dump"`
	CachePatch       string `json:"cache_patch_dump"`
	Consumer         string `json:"consumer_result"`
	Accepted         bool   `json:"state_value_accepted"`
}
type row struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool) {
	if !ok {
		panic("cache read experiment selection refused")
	}
}
func digest(raw []byte) string { x := sha256.Sum256(raw); return hex.EncodeToString(x[:]) }
func unhex(text string, size int) []byte {
	raw, err := hex.DecodeString(text)
	must(err)
	require(hex.EncodeToString(raw) == text && (size < 0 || len(raw) == size))
	return raw
}
func address(text string) types.Address {
	a, err := types.BytesToAddress(unhex(text, 20))
	must(err)
	return a
}
func hash(text string) types.Hash { var h types.Hash; copy(h[:], unhex(text, 32)); return h }
func class(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, leveldb.ErrClosed) {
		return "leveldb-closed"
	}
	return "other"
}
func inspect(root string) map[string]any {
	handle, err := leveldb.OpenFile(filepath.Join(root, "cache"), &opt.Options{ErrorIfMissing: true, ReadOnly: true, BlockCacheCapacity: 1 << 20, OpenFilesCacheCapacity: 16})
	must(err)
	defer func() { must(handle.Close()) }()
	iter := handle.NewIterator(nil, nil)
	defer iter.Release()
	rows := []row{}
	sum := sha256.New()
	var previous []byte
	for iter.Next() {
		key, value := iter.Key(), iter.Value()
		require(len(rows) < 16 && len(key) > 0 && len(key) <= 256 && len(value) <= 4096 && (previous == nil || bytes.Compare(previous, key) < 0))
		must(binary.Write(sum, binary.BigEndian, uint64(len(key))))
		_, err = sum.Write(key)
		must(err)
		must(binary.Write(sum, binary.BigEndian, uint64(len(value))))
		_, err = sum.Write(value)
		must(err)
		rows = append(rows, row{hex.EncodeToString(key), hex.EncodeToString(value)})
		previous = append(previous[:0], key...)
	}
	must(iter.Error())
	return map[string]any{"rows": rows, "records": len(rows), "sha256": hex.EncodeToString(sum.Sum(nil))}
}
func main() {
	mode := flag.String("case", "", "initialize-extract-query-close or reopen-query-close")
	root := flag.String("root", "", "owned case directory")
	fixturePath := flag.String("fixture", "", "independently selected fixture")
	fixtureSHA := flag.String("fixture-sha256", "", "selected fixture SHA-256")
	flag.Parse()
	require(flag.NArg() == 0 && *root != "" && (*mode == "initialize-extract-query-close" || *mode == "reopen-query-close"))
	info, err := os.Lstat(*root)
	must(err)
	require(info.IsDir() && info.Mode()&os.ModeSymlink == 0)
	entries, err := os.ReadDir(*root)
	must(err)
	if *mode == "initialize-extract-query-close" {
		require(len(entries) == 0)
	} else {
		require(len(entries) == 1 && entries[0].Name() == "cache" && entries[0].IsDir())
	}
	raw, err := os.ReadFile(*fixturePath)
	must(err)
	require(len(raw) <= 16384 && digest(raw) == *fixtureSHA)
	var f fixture
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	must(decoder.Decode(&f))
	var trailing any
	require(decoder.Decode(&trailing) == io.EOF)
	require(f.Schema == "cache-read-errors-component-fixture-v1" && f.OriginalRevision == "9c71ae82fc983e16f914ae085d4034030c8ebe3b" && f.ParentRuntime == "69b0844bccc68273b2b367cda7706d933d45358f" && f.MomentumHeight == 2 && f.Consumer == "REFUSED" && !f.Accepted)
	subject, absent := address(f.Subject), address(f.Absent)
	require(subject != absent && bytes.Equal(types.PlasmaContract.Bytes(), unhex(f.PlasmaContract, 20)))
	identifier := types.HashHeight{Hash: hash(f.MomentumHash), Height: f.MomentumHeight}
	spork := &types.ImplementedSpork{SporkId: hash(f.Spork)}
	encoder := json.NewEncoder(os.Stdout)
	emit := func(stage string, values map[string]any) {
		values["case"] = *mode
		values["stage"] = stage
		must(encoder.Encode(values))
	}
	emit("selection", map[string]any{"fixture_sha256": *fixtureSHA, "cache_manager_selected": true, "account_patch_extractor_selected": true, "public_Chain_selected": false, "ledger_or_state_tree_selected": false, "full_node_or_consensus_executed": false, "wallet_signing_or_network": false, "consumer_result": "REFUSED"})
	if *mode == "reopen-query-close" {
		emit("closed-store-before-reopen", inspect(*root))
	}
	manager := storage.NewCacheDBManager(*root)
	defer func() { _ = manager.Stop() }()
	query := func(view store.Cache, checkpoint, method, selection string, selected types.Address) {
		values := map[string]any{"checkpoint": checkpoint, "method": method, "selection": selection, "integer": nil, "boolean": nil, "error": "none"}
		if method == "spork" {
			value, err := view.IsSporkActive(spork)
			values["boolean"] = value
			values["error"] = class(err)
		} else {
			var value *big.Int
			var err error
			if method == "plasma" {
				value, err = view.GetChainPlasma(selected)
			} else {
				require(method == "stake")
				value, err = view.GetStakeBeneficialAmount(selected)
			}
			if value != nil {
				values["integer"] = value.String()
			}
			values["error"] = class(err)
		}
		emit("query", values)
	}
	if *mode == "initialize-extract-query-close" {
		empty := cache.NewCacheStore(types.ZeroHashHeight, manager)
		require(empty != nil)
		for _, method := range []string{"plasma", "stake", "spork"} {
			query(empty, "empty", method, "subject", subject)
		}
		patch := db.NewPatch()
		patch.Put(unhex(f.PlasmaKey, -1), unhex(f.PlasmaValue, 32))
		patch.Put(unhex(f.FusedKey, -1), unhex(f.FusedValue, 32))
		require(hex.EncodeToString(patch.Dump()) == f.InputPatch)
		detailed := &nom.DetailedMomentum{Momentum: &nom.Momentum{Hash: identifier.Hash, Height: identifier.Height},
			AccountBlocks: []*nom.AccountBlock{{Address: subject, Height: 1, MomentumAcknowledged: types.ZeroHashHeight}}}
		must(empty.ApplyMomentum(detailed, patch))
		changes, err := empty.Changes()
		must(err)
		require(hex.EncodeToString(changes.Dump()) == f.CachePatch)
		dump := append([]byte(nil), changes.Dump()...)
		must(manager.Add(identifier, changes))
		emit("extracted", map[string]any{"input_patch_dump": f.InputPatch, "cache_patch_dump": hex.EncodeToString(dump), "nonempty_account_block_rows": 1, "nominal_momentum_hash": f.MomentumHash, "nominal_momentum_height": f.MomentumHeight, "network_valid_momentum_or_account_execution": false})
	}
	view := cache.NewCacheStore(identifier, manager)
	require(view != nil && view.Identifier() == identifier)
	query(view, "populated", "plasma", "subject", subject)
	query(view, "populated", "stake", "subject", subject)
	query(view, "populated", "spork", "subject", subject)
	query(view, "populated", "plasma", "absent", absent)
	query(view, "populated", "stake", "absent", absent)
	rawView := manager.DB()
	require(rawView != nil)
	must(manager.Stop())
	must(manager.Stop())
	require(manager.DB() == nil)
	emit("manager-stopped", map[string]any{"first_stop": "none", "second_stop": "none", "manager_DB_nil": true, "borrowed_views_retained": true})
	iter := rawView.NewIterator(nil)
	last := iter.Last()
	iteratorErr := iter.Error()
	iter.Release()
	emit("closed-iterator", map[string]any{"last": last, "error": class(iteratorErr), "released": true})
	for _, method := range []string{"plasma", "stake", "spork"} {
		query(view, "closed", method, "subject", subject)
	}
	emit("closed-store", inspect(*root))
	fmt.Fprintln(os.Stderr, "CACHE_READ_ERROR_PROCESS_COMPLETE")
}
