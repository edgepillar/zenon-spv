//go:build candidate_cache_store_identifier_context

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
	mode := flag.String("case", "", "initialize-and-query or reopen-and-query")
	root := flag.String("root", "", "owned case directory")
	fixturePath := flag.String("fixture", "", "preselected source-genesis fixture")
	fixtureSHA := flag.String("fixture-sha256", "", "preselected fixture digest")
	flag.Parse()
	require(flag.NArg() == 0 && *root != "" && (*mode == "initialize-and-query" || *mode == "reopen-and-query"), "selected invocation")
	st, err := os.Lstat(*root)
	must(err)
	require(st.IsDir() && st.Mode()&os.ModeSymlink == 0, "ordinary owned case directory")
	entries, err := os.ReadDir(*root)
	must(err)
	if *mode == "initialize-and-query" {
		require(len(entries) == 0, "fresh case required")
	} else {
		require(len(entries) == 3, "three selected closed stores")
		for _, entry := range entries {
			require(entry.IsDir() && (entry.Name() == "ledger" || entry.Name() == "cache" || entry.Name() == "tree"), "selected stores")
		}
	}
	raw, err := os.ReadFile(*fixturePath)
	must(err)
	require(len(raw) <= 65536 && sum(raw) == *fixtureSHA, "fixture digest and size")
	var f fixture
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	must(decoder.Decode(&f))
	var trailing any
	require(decoder.Decode(&trailing) == io.EOF, "exact fixture JSON")
	require(f.Schema == "zenon-public-chain-reorg-reopen-fixture-v1" && f.Source.Revision == "9c71ae82fc983e16f914ae085d4034030c8ebe3b" &&
		f.Source.RuntimeTree == "d56bf37a23ddf0ec0f8af2eca62be01bb6c54dbc" && f.Unsigned && !f.Consensus && !f.Network && f.Consumer == "REFUSED" && !f.Accepted, "source and authority")
	output := os.Stdout
	os.Stdout = os.Stderr
	log15.Root().SetHandler(log15.DiscardHandler())
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	encoder := json.NewEncoder(output)
	emit := func(stage string, fields map[string]any) {
		fields["case"] = *mode
		fields["stage"] = stage
		must(encoder.Encode(fields))
	}
	emit("selection", map[string]any{"fixture_sha256": *fixtureSHA, "consumer_result": "REFUSED", "public_read_only_cache_context_selected": true,
		"new_account_blocks_added": false, "network_or_full_node_started": false, "consensus_validation_executed": false,
		"wallet_signing_or_broadcast": false, "cache_value_correctness_or_state_proof_acceptance_qualified": false})
	if *mode == "reopen-and-query" {
		emit("closed-stores-before-reopen", map[string]any{"images": images(*root)})
	}
	g, err := genesis.MakeEmbeddedGenesisConfig()
	must(err)
	first := g.GetGenesisMomentum()
	genesisDump := g.GetGenesisTransaction().Changes.Dump()
	require(first.Identifier() == id(f.States["A1"].Identifier) && first.Hash == first.ComputeHash() && first.Version == 1 &&
		first.StateRoot == types.ZeroHash && sum(genesisDump) == f.Source.GenesisPatch.SHA256 && len(genesisDump) == f.Source.GenesisPatch.Bytes, "independently fixed source genesis")
	emit("fresh-source-genesis", map[string]any{"identifier": first.Identifier(), "patch_sha256": sum(genesisDump), "patch_bytes": len(genesisDump)})
	c := chain.NewChain(db.NewLevelDBManager(filepath.Join(*root, "ledger")), storage.NewCacheDBManager(*root), g, filepath.Join(*root, "tree"), false)
	defer func() { _ = c.Stop() }()
	must(c.Init())
	require(c.StateTreeReady(), "tree ready after Init")
	must(c.Start())
	require(c.StateTreeReady(), "tree ready after Start")
	canonical := first.Identifier()
	require(c.GetFrontierMomentumStore().Identifier() == canonical && c.GetFrontierCacheStore().Identifier() == canonical, "exact real-manager frontier identities")
	rawKey := unhex(f.Key, 32)
	address, err := types.BytesToAddress(rawKey[1 : 1+types.AddressSize])
	must(err)
	emit("ready", map[string]any{"ledger": c.GetFrontierMomentumStore().Identifier(), "cache": c.GetFrontierCacheStore().Identifier(), "query_address_hex": hex.EncodeToString(address.Bytes())})
	foreignFirst, foreignLast, future := canonical, canonical, canonical
	foreignFirst.Hash[0] ^= 0x80
	foreignLast.Hash[len(foreignLast.Hash)-1] ^= 0x80
	future.Height++
	selections := []struct {
		name       string
		identifier types.HashHeight
		expected   bool
		rootError  string
	}{
		{"canonical-origin", canonical, true, "none"},
		{"same-height-first-byte-flip", foreignFirst, false, "identity-mismatch"},
		{"same-height-last-byte-flip", foreignLast, false, "identity-mismatch"},
		{"unavailable-next-height", future, false, "missing-version"},
	}
	for _, selection := range selections {
		cached := c.GetCacheStore(selection.identifier)
		fields := map[string]any{"name": selection.name, "requested_identifier": selection.identifier, "expected_available": selection.expected,
			"returned": cached != nil, "contract_mismatch": (cached != nil) != selection.expected, "cache_values_used_as_state_proof": false}
		if cached != nil {
			fields["reported_identifier"] = cached.Identifier()
			plasma, plasmaErr := cached.GetChainPlasma(address)
			fused, fusedErr := cached.GetStakeBeneficialAmount(address)
			fields["chain_plasma_error"], fields["fused_error"] = errClass(plasmaErr), errClass(fusedErr)
			if plasmaErr == nil {
				fields["chain_plasma"] = plasma.String()
			}
			if fusedErr == nil {
				fields["fused_amount"] = fused.String()
			}
		}
		stateRoot, rootErr := c.StateRoot(selection.identifier)
		require(errClass(rootErr) == selection.rootError, "selected state-root identifier refusal")
		if rootErr == nil {
			require(stateRoot.String() == f.States["A1"].Root, "independent origin root")
		} else {
			require(stateRoot == types.ZeroHash, "no state root on refusal")
		}
		fields["state_root"], fields["state_root_error"] = stateRoot.String(), errClass(rootErr)
		emit("cache-context-query", fields)
	}
	must(c.Stop())
	emit("closed-stores", map[string]any{"images": images(*root)})
	fmt.Fprintln(os.Stderr, "CACHE_STORE_IDENTIFIER_CONTEXT_PROCESS_COMPLETE")
}
