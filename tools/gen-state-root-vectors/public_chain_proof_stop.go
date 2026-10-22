//go:build candidate_public_chain_proof_stop && (darwin || linux)

// SPDX-License-Identifier: GPL-3.0-only
// Observe public-call overlap with Stop; no internal database interleaving is claimed.
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
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/zenon-network/go-zenon/chain"
	"github.com/zenon-network/go-zenon/chain/cache/storage"
	"github.com/zenon-network/go-zenon/chain/genesis"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

const nodeRevision = "9c71ae82fc983e16f914ae085d4034030c8ebe3b"
const runtimeTree = "053c87e5bc4addd1bb70a467cb34facd439e66bc"

type selection struct {
	Schema   string `json:"schema"`
	Revision string `json:"node_revision"`
	Tree     string `json:"runtime_tree"`
	Patch    struct {
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
	} `json:"genesis_patch"`
	Identifier struct {
		Hash   string `json:"hash"`
		Height uint64 `json:"height"`
	} `json:"genesis_identifier"`
	Keys []struct {
		Domain string `json:"domain"`
		Key    string `json:"raw_key"`
	} `json:"keys"`
	Workers        int    `json:"workers"`
	StopAfter      int    `json:"stop_after_completed_pairs"`
	Warmup         int    `json:"warmup_pairs"`
	Requests       int    `json:"concurrent_request_pairs"`
	Post           int    `json:"post_Stop_request_pairs"`
	Trigger        string `json:"stop_trigger"`
	AcceptedHeader bool   `json:"accepted_header_binding"`
	AcceptedValue  bool   `json:"production_state_value_accepted"`
	Consumer       string `json:"consumer_result"`
}
type rootObservation struct {
	Error *string `json:"error"`
	Hash  string  `json:"hash"`
}
type proofObservation struct {
	Error     *string `json:"error"`
	RowSHA256 *string `json:"row_sha256"`
	ValueNil  bool    `json:"value_nil"`
	ProofNil  bool    `json:"proof_nil"`
}
type callObservation struct {
	Index      int              `json:"index"`
	Worker     int              `json:"worker"`
	KeyIndex   int              `json:"key_index"`
	RootStart  int64            `json:"Root_start_ns"`
	RootEnd    int64            `json:"Root_end_ns"`
	ProofStart int64            `json:"GetProof_start_ns"`
	ProofEnd   int64            `json:"GetProof_end_ns"`
	Root       rootObservation  `json:"Root"`
	Proof      proofObservation `json:"GetProof"`
}
type stopObservation struct {
	Start        int64   `json:"start_ns"`
	End          int64   `json:"end_ns"`
	Error        *string `json:"error"`
	ReadyAfter   bool    `json:"ready_after"`
	Calls        int     `json:"calls"`
	CleanupError *string `json:"idempotent_cleanup_error"`
}
type report struct {
	Schema         string            `json:"schema"`
	Profile        string            `json:"profile"`
	Revision       string            `json:"node_revision"`
	Tree           string            `json:"runtime_tree"`
	WireSHA256     string            `json:"wire_sha256"`
	Race           bool              `json:"build_race_enabled"`
	InitReady      bool              `json:"init_ready"`
	WarmupEnd      int64             `json:"warmup_completed_ns"`
	Warmup         []string          `json:"warmup_row_sha256s"`
	Calls          []callObservation `json:"calls"`
	Post           callObservation   `json:"post_Stop"`
	Stop           stopObservation   `json:"Stop"`
	Total          int64             `json:"component_total_ns"`
	Consumer       string            `json:"consumer_result"`
	AcceptedHeader bool              `json:"accepted_header_binding"`
	AcceptedValue  bool              `json:"production_state_value_accepted"`
	ChainStart     bool              `json:"Chain_Start_selected"`
	Node           bool              `json:"Node_entrypoint_selected"`
	Wallet         bool              `json:"wallet_or_signing_or_user_transaction_selected"`
	Network        bool              `json:"chain_networking_selected"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool, why string) {
	if !ok {
		panic(why)
	}
}
func sum(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func framed(root types.Hash, key, value, proof []byte) string {
	var out bytes.Buffer
	for _, raw := range [][]byte{key, value, root[:], proof} {
		if raw == nil {
			out.WriteByte(0)
		} else {
			out.WriteByte(1)
		}
		must(binary.Write(&out, binary.BigEndian, uint64(len(raw))))
		_, err := out.Write(raw)
		must(err)
	}
	return sum(out.Bytes())
}
func checkFraming() {
	var root types.Hash
	for i := range root {
		root[i] = byte(i)
	}
	// Independently framed vectors distinguish an absent value from empty bytes.
	require(framed(root, []byte("k"), nil, []byte("p")) == "7e6c942b4713bf5ebb058f7b315e0052a31b4d0317aede5d091cf1195d2004de", "canonical absent-value frame")
	require(framed(root, []byte("k"), []byte{}, []byte("p")) == "53703a23461aa6323df7ba0d4fef5e1de90c1afc5a8018e869fb8eccc44b12de", "canonical empty-value frame")
}
func classify(err error) *string {
	if err == nil {
		return nil
	}
	value := "unselected_error"
	if errors.Is(err, chain.ErrStateTreeNotReady) {
		value = "state_tree_not_ready"
	} else if errors.Is(err, leveldb.ErrClosed) {
		value = "leveldb_closed"
	} else {
		// Detailed failures remain private capture material, never a successful witness.
		fmt.Fprintf(os.Stderr, "unselected component error: %v\n", err)
	}
	return &value
}
func main() {
	origin := time.Now()
	root := flag.String("root", "", "new empty owned case directory")
	input := flag.String("selection", "", "blinded key selection")
	pin := flag.String("selection-sha256", "", "exact blinded input digest")
	flag.Parse()
	checkFraming()
	require(flag.NArg() == 0 && filepath.IsAbs(*root) && filepath.Clean(*root) == *root && len(*pin) == 64, "selected invocation")
	for p := filepath.Clean(*root); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		must(err)
		require(info.IsDir() && info.Mode()&os.ModeSymlink == 0, "ordinary directory ancestors")
		if filepath.Dir(p) == p {
			break
		}
	}
	entries, err := os.ReadDir(*root)
	must(err)
	require(len(entries) == 0, "new empty case required")
	file, err := os.Open(*input)
	must(err)
	raw, err := io.ReadAll(io.LimitReader(file, (128<<10)+1))
	must(err)
	must(file.Close())
	require(len(raw) <= 128<<10 && sum(raw) == *pin, "bounded pinned wire input")
	var selected selection
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	must(decoder.Decode(&selected))
	var trailing any
	require(decoder.Decode(&trailing) == io.EOF, "exact input JSON")
	require(selected.Schema == "source-genesis-public-Chain-proof-Stop-selection-v1" && selected.Revision == nodeRevision && selected.Tree == runtimeTree &&
		selected.Workers == 16 && selected.StopAfter == 32 && selected.Warmup == 128 && selected.Requests == 2048 && selected.Post == 1 && len(selected.Keys) == 128 &&
		selected.Trigger == "after 32 completed concurrent query pairs; successful caller intervals must overlap Stop" &&
		!selected.AcceptedHeader && !selected.AcceptedValue && selected.Consumer == "REFUSED", "fixed component scope")
	keys := make([][]byte, len(selected.Keys))
	seen := map[string]bool{}
	for i, key := range selected.Keys {
		value, err := hex.DecodeString(key.Key)
		must(err)
		require(len(value) > 0 && len(value) <= 4096 && hex.EncodeToString(value) == key.Key && !seen[key.Key], "distinct canonical keys")
		require(key.Domain == "balance" || key.Domain == "contract_storage" || key.Domain == "absent_balance" || key.Domain == "excluded_ledger_key", "selected projection domains")
		seen[key.Key] = true
		keys[i] = value
	}
	info, ok := debug.ReadBuildInfo()
	require(ok, "ordinary build information")
	race := false
	for _, setting := range info.Settings {
		if setting.Key == "-race" {
			require(setting.Value == "true", "race setting")
			race = true
		}
	}
	profile := "ordinary"
	if race {
		profile = "race"
	}
	output := os.Stdout
	os.Stdout = os.Stderr
	log15.Root().SetHandler(log15.DiscardHandler())
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	config, err := genesis.MakeEmbeddedGenesisConfig()
	must(err)
	first := config.GetGenesisMomentum()
	dump := config.GetGenesisTransaction().Changes.Dump()
	require(first.Hash == first.ComputeHash() && first.Hash.String() == selected.Identifier.Hash && first.Height == selected.Identifier.Height &&
		first.Height == 1 && first.Version == 1 && first.StateRoot == types.ZeroHash && len(first.PublicKey) == 0 && len(first.Signature) == 0 &&
		len(dump) == selected.Patch.Bytes && sum(dump) == selected.Patch.SHA256, "selected unsigned source genesis")
	c := chain.NewChain(db.NewLevelDBManager(filepath.Join(*root, "ledger")), storage.NewCacheDBManager(*root), config, filepath.Join(*root, "tree"), false)
	closed := false
	defer func() {
		if !closed {
			_ = c.Stop()
		}
	}()
	must(c.Init())
	require(c.StateTreeReady() && c.GetFrontierMomentumStore().Identifier() == first.Identifier() && c.GetFrontierCacheStore().Identifier() == first.Identifier(), "real managers at full source identity")
	begin := make(chan struct{})
	var completed atomic.Int64
	ns := func() int64 { return time.Since(origin).Nanoseconds() }
	observe := func(index, worker int) callObservation {
		row := callObservation{Index: index, Worker: worker, KeyIndex: index % len(keys)}
		key := keys[row.KeyIndex]
		row.RootStart = ns()
		value, err := c.StateRoot(first.Identifier())
		row.RootEnd = ns()
		row.Root = rootObservation{Error: classify(err), Hash: value.String()}
		row.ProofStart = ns()
		stored, proof, err := c.GetProof(first.Identifier(), key)
		row.ProofEnd = ns()
		row.Proof = proofObservation{Error: classify(err), ValueNil: stored == nil, ProofNil: proof == nil}
		if err == nil {
			digest := framed(value, key, stored, proof)
			row.Proof.RowSHA256 = &digest
		}
		return row
	}
	warmup := make([]string, len(keys))
	for i := range keys {
		row := observe(i, 0)
		require(row.Root.Error == nil && row.Proof.Error == nil && row.Proof.RowSHA256 != nil, "complete warmup")
		warmup[i] = *row.Proof.RowSHA256
	}
	warmupEnd := ns()
	stopDone := make(chan stopObservation, 1)
	go func() {
		<-begin
		row := stopObservation{Start: ns(), Calls: 1}
		err := c.Stop()
		row.End = ns()
		row.Error = classify(err)
		row.ReadyAfter = c.StateTreeReady()
		stopDone <- row
	}()
	rows := make([]callObservation, selected.Requests)
	var workers sync.WaitGroup
	workers.Add(selected.Workers)
	for worker := 0; worker < selected.Workers; worker++ {
		go func(worker int) {
			defer workers.Done()
			for index := worker; index < len(rows); index += selected.Workers {
				rows[index] = observe(index, worker)
				if completed.Add(1) == int64(selected.StopAfter) {
					close(begin)
				}
			}
		}(worker)
	}
	workers.Wait()
	stopped := <-stopDone
	post := observe(0, 0)
	stopped.CleanupError = classify(c.Stop())
	stopped.Calls++
	closed = true
	result := report{Schema: "public-Chain-proof-Stop-process-v1", Profile: profile, Revision: nodeRevision, Tree: runtimeTree,
		WireSHA256: *pin, Race: race, InitReady: true, WarmupEnd: warmupEnd, Warmup: warmup, Calls: rows, Post: post, Stop: stopped, Total: ns(), Consumer: "REFUSED"}
	must(json.NewEncoder(output).Encode(result))
}
