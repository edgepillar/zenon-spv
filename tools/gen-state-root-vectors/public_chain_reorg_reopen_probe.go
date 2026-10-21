//go:build candidate_public_chain_reorg_reopen

// SPDX-License-Identifier: GPL-3.0-only
// Exercise real public Chain maintenance on fresh unsigned local fixtures.
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
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
)

type identifier struct {
	Hash   string `json:"hash"`
	Height uint64 `json:"height"`
}
type header struct {
	Version         uint64 `json:"version"`
	ChainIdentifier uint64 `json:"chain_identifier"`
	PreviousHash    string `json:"previous_hash"`
	Height          uint64 `json:"height"`
	Timestamp       uint64 `json:"timestamp_unix"`
	ChangesHash     string `json:"changes_hash"`
	Hash            string `json:"hash"`
	Data            string `json:"data_hex"`
	ContentCount    int    `json:"content_count"`
	Preimage        string `json:"preimage_hex"`
	PublicKeyBytes  int    `json:"public_key_bytes"`
	SignatureBytes  int    `json:"signature_bytes"`
	StateRoot       string `json:"state_root"`
}
type selectedState struct {
	Identifier  identifier `json:"identifier"`
	Root        string     `json:"root"`
	Present     bool       `json:"present"`
	Value       string     `json:"value"`
	Proof       string     `json:"proof"`
	Header      *header    `json:"header"`
	PatchDump   *string    `json:"patch_dump"`
	PatchSHA256 *string    `json:"patch_sha256"`
}
type fixture struct {
	Schema string `json:"schema"`
	Source struct {
		Repository   string `json:"node_repository"`
		Revision     string `json:"original_revision"`
		RuntimeTree  string `json:"experimental_runtime_tree"`
		SeedSHA256   string `json:"seed_file_sha256"`
		GenesisPatch struct {
			SHA256 string `json:"sha256"`
			Bytes  int    `json:"bytes"`
		} `json:"genesis_patch"`
	} `json:"source"`
	Key          string                   `json:"raw_key"`
	Path         string                   `json:"path"`
	States       map[string]selectedState `json:"states"`
	Steps        []string                 `json:"steps"`
	Processes    []string                 `json:"processes"`
	EmptyControl string                   `json:"preexisting_empty_v1_control"`
	Unsigned     bool                     `json:"unsigned_local_component_fixture"`
	Consensus    bool                     `json:"full_consensus_validation_executed"`
	Network      bool                     `json:"network_started"`
	Consumer     string                   `json:"consumer_result"`
	Accepted     bool                     `json:"production_state_value_accepted"`
}
type image struct {
	Records          uint64 `json:"records"`
	KeyBytes         uint64 `json:"key_bytes"`
	ValueBytes       uint64 `json:"value_bytes"`
	ZeroLengthValues uint64 `json:"zero_length_values"`
	SHA256           string `json:"sha256"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}
func sum(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
func unhex(text string, length int) []byte {
	raw, err := hex.DecodeString(text)
	must(err)
	require(hex.EncodeToString(raw) == text && (length < 0 || len(raw) == length), "selected hex")
	return raw
}
func hash(text string) types.Hash {
	var out types.Hash
	copy(out[:], unhex(text, 32))
	return out
}
func id(x identifier) types.HashHeight { return types.HashHeight{Hash: hash(x.Hash), Height: x.Height} }
func errClass(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, trie.ErrNoVersion) {
		return "missing-version"
	}
	if errors.Is(err, trie.ErrVersionIdentityMismatch) {
		return "identity-mismatch"
	}
	return "other"
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
		key, value := iter.Key(), iter.Value()
		require(len(key) > 0 && len(key) <= 256 && len(value) <= 16<<20 && out.Records < 1000000 && (previous == nil || bytes.Compare(previous, key) < 0), "raw image bounds/order")
		must(binary.Write(digest, binary.BigEndian, uint64(len(key))))
		_, err = digest.Write(key)
		must(err)
		must(binary.Write(digest, binary.BigEndian, uint64(len(value))))
		_, err = digest.Write(value)
		must(err)
		out.Records++
		out.KeyBytes += uint64(len(key))
		out.ValueBytes += uint64(len(value))
		if len(value) == 0 {
			out.ZeroLengthValues++
		}
		previous = append(previous[:0], key...)
	}
	must(iter.Error())
	iter.Release()
	out.SHA256 = hex.EncodeToString(digest.Sum(nil))
	return out
}
func images(root string) map[string]image {
	return map[string]image{"ledger": inspect(filepath.Join(root, "ledger")), "cache": inspect(filepath.Join(root, "cache")), "tree": inspect(filepath.Join(root, "tree"))}
}
func main() {
	mode := flag.String("case", "", "advance-reorg or fresh-process reopen")
	root := flag.String("root", "", "owned case directory")
	fixturePath := flag.String("fixture", "", "preselected fixture")
	fixtureSHA := flag.String("fixture-sha256", "", "preselected fixture digest")
	flag.Parse()
	require(flag.NArg() == 0 && *root != "" && (*mode == "advance-reorg" || *mode == "reopen"), "selected invocation")
	st, err := os.Lstat(*root)
	must(err)
	require(st.IsDir() && st.Mode()&os.ModeSymlink == 0, "owned ordinary case directory")
	entries, err := os.ReadDir(*root)
	must(err)
	if *mode == "advance-reorg" {
		require(len(entries) == 0, "fresh case required")
	} else {
		require(len(entries) == 3, "three selected real stores")
		for _, e := range entries {
			require(e.IsDir() && (e.Name() == "ledger" || e.Name() == "cache" || e.Name() == "tree"), "selected store namespace")
		}
	}
	raw, err := os.ReadFile(*fixturePath)
	must(err)
	require(len(raw) <= 65536 && sum(raw) == *fixtureSHA, "fixture digest/size")
	var f fixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	must(dec.Decode(&f))
	var trailing any
	require(dec.Decode(&trailing) == io.EOF, "exact fixture JSON")
	require(f.Schema == "zenon-public-chain-reorg-reopen-fixture-v1" && f.Source.Revision == "9c71ae82fc983e16f914ae085d4034030c8ebe3b" &&
		f.Source.RuntimeTree == "d56bf37a23ddf0ec0f8af2eca62be01bb6c54dbc" && len(f.States) == 5 &&
		f.Unsigned && !f.Consensus && !f.Network && f.Consumer == "REFUSED" && !f.Accepted, "fixture source/authority")
	key := unhex(f.Key, 32)
	require(f.Key == "0300000000000000000000000000000000000000000304066318c6318c6318c6" && types.NewHash(key).String() == f.Path, "selected key/path")
	output := os.Stdout
	os.Stdout = os.Stderr
	log15.Root().SetHandler(log15.DiscardHandler())
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	enc := json.NewEncoder(output)
	emit := func(stage string, fields map[string]any) {
		fields["case"] = *mode
		fields["stage"] = stage
		must(enc.Encode(fields))
	}
	emit("selection", map[string]any{"fixture_sha256": *fixtureSHA, "raw_key": f.Key, "unsigned_local_component_fixture": true,
		"public_Chain_Init_and_Start_selected": true, "full_node_or_network_started": false, "consensus_validation_executed": false,
		"wallet_signing_or_broadcast": false, "cache_account_block_extraction_selected": false, "consumer_result": "REFUSED"})
	var before map[string]image
	if *mode == "reopen" {
		before = images(*root)
		emit("closed-stores-before-reopen", map[string]any{"images": before})
	}
	g, err := genesis.MakeEmbeddedGenesisConfig()
	must(err)
	first := g.GetGenesisMomentum()
	dump := g.GetGenesisTransaction().Changes.Dump()
	require(first.Identifier() == id(f.States["A1"].Identifier) && first.Hash == first.ComputeHash() && first.Version == 1 &&
		first.ChainIdentifier == 1 && first.TimestampUnix == 1637755200 && first.StateRoot == types.ZeroHash && len(first.PublicKey) == 0 &&
		len(first.Signature) == 0 && len(dump) == f.Source.GenesisPatch.Bytes && sum(dump) == f.Source.GenesisPatch.SHA256, "fresh source genesis")
	emit("fresh-source-genesis", map[string]any{"identifier": first.Identifier(), "patch_sha256": sum(dump), "patch_bytes": len(dump)})
	c := chain.NewChain(db.NewLevelDBManager(filepath.Join(*root, "ledger")), storage.NewCacheDBManager(*root), g, filepath.Join(*root, "tree"), false)
	defer func() { _ = c.Stop() }()
	must(c.Init())
	require(c.StateTreeReady(), "tree ready after Init")
	must(c.Start())
	require(c.StateTreeReady(), "tree ready after Start")
	frontiers := func(want string) map[string]any {
		expected := id(f.States[want].Identifier)
		ledger := c.GetFrontierMomentumStore()
		cache := c.GetFrontierCacheStore()
		require(ledger != nil && cache != nil && ledger.Identifier() == expected && cache.Identifier() == expected && c.StateTreeReady(), "exact real-manager frontiers")
		return map[string]any{"ledger": ledger.Identifier(), "cache": cache.Identifier(), "ready": c.StateTreeReady()}
	}
	query := func(stage, name string, selection types.HashHeight, wantError string) {
		got, rootErr := c.StateRoot(selection)
		value, proof, proofErr := c.GetProof(selection, key)
		require(errClass(rootErr) == wantError && errClass(proofErr) == wantError, "selected root/proof error class")
		if wantError == "none" {
			expected := f.States[name]
			require(got.String() == expected.Root && (value != nil) == expected.Present && hex.EncodeToString(value) == expected.Value && hex.EncodeToString(proof) == expected.Proof, "independently selected root/value/proof")
		} else {
			require(got == types.ZeroHash && value == nil && proof == nil, "no result on refused version")
		}
		emit("query", map[string]any{"checkpoint": stage, "selection": name, "identifier": selection, "root": got.String(), "value": hex.EncodeToString(value),
			"present": value != nil, "proof": hex.EncodeToString(proof), "root_error": errClass(rootErr), "proof_error": errClass(proofErr)})
	}
	checkpoint := func(stage, tip string, accepted []string, refused [][2]string) {
		emit("frontiers", map[string]any{"checkpoint": stage, "tip": tip, "frontiers": frontiers(tip)})
		for _, name := range accepted {
			query(stage, name, id(f.States[name].Identifier), "none")
		}
		for _, row := range refused {
			query(stage, row[0], id(f.States[row[0]].Identifier), row[1])
		}
		wrong := id(f.States[tip].Identifier)
		wrong.Hash[0] ^= 1
		query(stage, "same-height-foreign-"+tip, wrong, "identity-mismatch")
	}
	makePatch := func(name string) db.Patch {
		row := f.States[name]
		require(row.Header != nil && row.PatchDump != nil && row.PatchSHA256 != nil, "selected append state")
		patch := db.NewPatch()
		if row.Present {
			patch.Put(key, unhex(row.Value, 32))
		} else {
			patch.Delete(key)
		}
		actual := patch.Dump()
		require(hex.EncodeToString(actual) == *row.PatchDump && sum(actual) == *row.PatchSHA256 && db.PatchHash(patch).String() == row.Header.ChangesHash, "independent batch encoding")
		return patch
	}
	appendState := func(name, previous string) {
		row := f.States[name]
		h := row.Header
		patch := makePatch(name)
		require(h.Version == 1 && h.ChainIdentifier == 1 && h.PreviousHash == f.States[previous].Identifier.Hash && h.Height == f.States[previous].Identifier.Height+1 &&
			h.Data == "" && h.ContentCount == 0 && h.PublicKeyBytes == 0 && h.SignatureBytes == 0 && hash(h.StateRoot) == types.ZeroHash, "unsigned selected header fields")
		m := &nom.Momentum{Version: h.Version, ChainIdentifier: h.ChainIdentifier, PreviousHash: hash(h.PreviousHash), Height: h.Height, TimestampUnix: h.Timestamp, ChangesHash: hash(h.ChangesHash)}
		m.Hash = m.ComputeHash()
		require(m.Identifier() == id(row.Identifier) && m.Hash.String() == h.Hash, "independent v1 identifier")
		prior := frontiers(previous)
		priorRoot, err := c.StateRoot(id(f.States[previous].Identifier))
		must(err)
		projected, err := c.ComputeStateRoot(id(f.States[previous].Identifier), patch)
		must(err)
		repeated, err := c.ComputeStateRoot(id(f.States[previous].Identifier), patch)
		must(err)
		require(projected.String() == row.Root && repeated == projected, "selected speculative root")
		afterRoot, err := c.StateRoot(id(f.States[previous].Identifier))
		must(err)
		require(afterRoot == priorRoot, "projection leaves previous committed root unchanged")
		frontiers(previous)
		_, newErr := c.StateRoot(id(row.Identifier))
		require(errClass(newErr) == "missing-version", "projection does not commit new version")
		emit("projection", map[string]any{"selection": name, "previous": previous, "root": projected.String(), "repeated_root": repeated.String(),
			"new_version_error": errClass(newErr), "frontiers": prior, "previous_root_unchanged": true, "patch_dump": hex.EncodeToString(patch.Dump())})
		func() {
			locker := c.AcquireInsert("bounded unsigned reorg/reopen fixture")
			defer locker.Unlock()
			detailed := &nom.DetailedMomentum{Momentum: m}
			must(c.UpdateCache(locker, detailed, patch))
			require(c.GetFrontierMomentumStore().Identifier() == id(f.States[previous].Identifier) && c.GetFrontierCacheStore().Identifier() == m.Identifier(), "cache-first maintenance")
			must(c.UpdateStateTree(locker, detailed, patch))
			root, err := c.StateRoot(m.Identifier())
			must(err)
			require(root.String() == row.Root && c.GetFrontierMomentumStore().Identifier() == id(f.States[previous].Identifier), "tree-before-ledger maintenance")
			tx := &nom.MomentumTransaction{Momentum: m, Changes: patch}
			must(c.AddMomentumTransaction(locker, tx))
			require(tx.Changes == nil, "ledger consumes patch")
		}()
		emit("appended", map[string]any{"selection": name, "identifier": m.Identifier(), "frontiers": frontiers(name),
			"maintenance_order": []string{"UpdateCache", "UpdateStateTree", "AddMomentumTransaction"}, "patch_consumed": true})
	}
	refuseOldProjection := func(stage, wantError string) {
		got, err := c.ComputeStateRoot(id(f.States["A2"].Identifier), makePatch("A3"))
		require(errClass(err) == wantError && got == types.ZeroHash, "old full-identity projection refused")
		emit("old-projection-refused", map[string]any{"checkpoint": stage, "previous": "A2", "changes": "A3", "error": errClass(err), "root": got.String()})
	}
	if *mode == "advance-reorg" {
		checkpoint("initialized", "A1", []string{"A1"}, [][2]string{{"A2", "missing-version"}})
		appendState("A2", "A1")
		checkpoint("after-A2", "A2", []string{"A1", "A2"}, nil)
		appendState("A3", "A2")
		checkpoint("after-A3", "A3", []string{"A1", "A2", "A3"}, nil)
		func() {
			locker := c.AcquireInsert("bounded unsigned rollback fixture")
			defer locker.Unlock()
			target := id(f.States["A1"].Identifier)
			must(c.RollbackTo(locker, target))
			must(c.RollbackCacheTo(locker, target))
			must(c.TruncateStateTreeTo(locker, target))
		}()
		emit("rolled-back", map[string]any{"target": f.States["A1"].Identifier, "frontiers": frontiers("A1"),
			"maintenance_order": []string{"RollbackTo", "RollbackCacheTo", "TruncateStateTreeTo"}})
		checkpoint("after-rollback", "A1", []string{"A1"}, [][2]string{{"A2", "missing-version"}, {"A3", "missing-version"}})
		refuseOldProjection("after-rollback", "missing-version")
		appendState("B2", "A1")
		checkpoint("after-B2", "B2", []string{"A1", "B2"}, [][2]string{{"A2", "identity-mismatch"}, {"A3", "missing-version"}})
		appendState("B3", "B2")
		checkpoint("after-B3", "B3", []string{"A1", "B2", "B3"}, [][2]string{{"A2", "identity-mismatch"}, {"A3", "identity-mismatch"}})
		refuseOldProjection("after-B3", "identity-mismatch")
	} else {
		checkpoint("fresh-process-reopen", "B3", []string{"A1", "B2", "B3"}, [][2]string{{"A2", "identity-mismatch"}, {"A3", "identity-mismatch"}})
		refuseOldProjection("fresh-process-reopen", "identity-mismatch")
	}
	must(c.Stop())
	require(!c.StateTreeReady(), "not ready after Stop")
	must(c.Stop())
	require(!c.StateTreeReady(), "repeat Stop")
	after := images(*root)
	if before != nil {
		for _, name := range []string{"ledger", "cache", "tree"} {
			require(before[name] == after[name], "raw logical images unchanged on reopen")
		}
	}
	emit("closed-stores", map[string]any{"images": after, "ready": c.StateTreeReady(), "repeat_stop_error": nil,
		"raw_zero_length_values_retained": true, "fresh_process_reopen_images_unchanged": before != nil, "consumer_result": "REFUSED"})
	fmt.Fprintln(os.Stderr, "PUBLIC_CHAIN_REORG_REOPEN_PROCESS_COMPLETE")
}
