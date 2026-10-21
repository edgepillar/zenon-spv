//go:build candidate_zenon_worker_stop

// SPDX-License-Identifier: GPL-3.0-only
// Observe sequential core-manager shutdown without a wallet or a peer server.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/inconshreveable/log15"
	"github.com/zenon-network/go-zenon/chain"
	"github.com/zenon-network/go-zenon/chain/genesis"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
	"github.com/zenon-network/go-zenon/zenon"
)

type selection struct {
	Schema      string           `json:"schema"`
	Key         string           `json:"raw_key"`
	Genesis     types.HashHeight `json:"genesis"`
	PatchBytes  int              `json:"genesis_patch_bytes"`
	PatchSHA256 string           `json:"genesis_patch_sha256"`
}
type callResult struct {
	Error string `json:"error"`
	Panic string `json:"panic"`
}
type queryResult struct {
	Ready        bool   `json:"ready"`
	Root         string `json:"root"`
	Value        string `json:"value"`
	Present      bool   `json:"present"`
	Proof        string `json:"proof"`
	RootError    string `json:"root_error"`
	ProofError   string `json:"proof_error"`
	ForeignRoot  string `json:"foreign_root"`
	ForeignError string `json:"foreign_error"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func errorClass(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, chain.ErrStateTreeNotReady) {
		return "not-ready"
	}
	if errors.Is(err, trie.ErrVersionIdentityMismatch) {
		return "identity-mismatch"
	}
	return "other:" + err.Error()
}
func stop(v zenon.Zenon) (out callResult) {
	defer func() {
		if p := recover(); p != nil {
			out.Panic = fmt.Sprint(p)
		}
	}()
	if err := v.Stop(); err != nil {
		out.Error = err.Error()
	}
	return
}
func query(v zenon.Zenon, chosen selection, key []byte) queryResult {
	c := v.Chain()
	root, rootErr := c.StateRoot(chosen.Genesis)
	value, proof, proofErr := c.GetProof(chosen.Genesis, key)
	wrong := chosen.Genesis
	wrong.Hash[0] ^= 1
	foreign, foreignErr := c.StateRoot(wrong)
	return queryResult{Ready: c.StateTreeReady(), Root: root.String(), Value: hex.EncodeToString(value),
		Present: value != nil, Proof: hex.EncodeToString(proof), RootError: errorClass(rootErr),
		ProofError: errorClass(proofErr), ForeignRoot: foreign.String(), ForeignError: errorClass(foreignErr)}
}
func main() {
	mode := flag.String("case", "", "selected finite sequential case")
	root := flag.String("root", "", "caller-owned case directory")
	input := flag.String("selection", "", "sealed source-genesis selection")
	inputSHA := flag.String("selection-sha256", "", "sealed selection digest")
	flag.Parse()
	if flag.NArg() != 0 || (*mode != "construct-stop" && *mode != "init-stop" && *mode != "reopen-start-stop") {
		panic("unselected case")
	}
	stat, err := os.Lstat(*input)
	must(err)
	if !stat.Mode().IsRegular() || stat.Size() > 8192 {
		panic("selection bounds")
	}
	raw, err := os.ReadFile(*input)
	must(err)
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != *inputSHA {
		panic("selection digest")
	}
	var chosen selection
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	must(dec.Decode(&chosen))
	var trailing any
	if dec.Decode(&trailing) != io.EOF || chosen.Schema != "zenon-worker-stop-selection-v1" {
		panic("exact selection")
	}
	key, err := hex.DecodeString(chosen.Key)
	must(err)
	if len(key) != 32 || key[0] != 3 || key[21] != 3 {
		panic("selected key domain")
	}
	entries, err := os.ReadDir(*root)
	must(err)
	if (*mode == "reopen-start-stop") != (len(entries) > 0) {
		panic("fresh or retained root selection")
	}

	output := os.Stdout
	os.Stdout = os.Stderr
	log15.Root().SetHandler(log15.DiscardHandler())
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	g, err := genesis.MakeEmbeddedGenesisConfig()
	must(err)
	first := g.GetGenesisMomentum()
	patch := g.GetGenesisTransaction().Changes.Dump()
	patchHash := sha256.Sum256(patch)
	if first.Identifier() != chosen.Genesis || first.ComputeHash() != first.Hash || first.Version != 1 ||
		first.StateRoot != types.ZeroHash || len(first.PublicKey) != 0 || len(first.Signature) != 0 ||
		len(patch) != chosen.PatchBytes || hex.EncodeToString(patchHash[:]) != chosen.PatchSHA256 {
		panic("source genesis")
	}
	cfg := &zenon.Config{MinPeers: 1, MinConnectedPeers: 1, DataDir: *root, GenesisConfig: g,
		ProducingKeyPair: nil, StateTreeArchive: false}
	z, err := zenon.NewZenon(cfg)
	must(err)
	if z.Config().ProducingKeyPair != nil || z.Producer().GetCoinBase() != nil {
		panic("keyless selection")
	}
	initialized := *mode != "construct-stop"
	started := *mode == "reopen-start-stop"
	if initialized {
		must(z.Init())
	}
	if started {
		must(z.Start())
	}
	before := query(z, chosen, key)
	observed := stop(z)
	after := query(z, chosen, key)
	teardown := []zenon.CandidateWorkerStopCleanupResult{}
	if observed.Panic == "close of nil channel" {
		teardown = zenon.CandidateCleanupAfterWorkerStopPanic(z)
	}
	finalReady := z.Chain().StateTreeReady()
	report := map[string]any{
		"schema": "zenon-core-worker-stop-observation-v1", "case": *mode,
		"selection_sha256": *inputSHA, "genesis_identifier": chosen.Genesis,
		"genesis_patch_bytes": len(patch), "genesis_patch_sha256": hex.EncodeToString(patchHash[:]),
		"initialized": initialized, "core_started": started, "before_stop": before, "stop": observed,
		"after_stop": after, "caller_teardown_after_observation": teardown, "final_tree_ready": finalReady,
		"producing_key_configured": false, "wallet_manager_created": false,
		"node_wrapper_created": false, "p2p_server_created": false, "RPC_listener_started": false,
		"external_peer_configured": false, "production_state_value_accepted": false,
		"header_authentication_executed": false, "consumer_result": "REFUSED",
	}
	must(json.NewEncoder(output).Encode(report))
	fmt.Fprintln(os.Stderr, "ZENON_CORE_WORKER_STOP_PROCESS_COMPLETE")
	if observed.Error != "" || (observed.Panic != "" && observed.Panic != "close of nil channel") || finalReady {
		os.Exit(2)
	}
	for _, row := range teardown {
		if row.Error != "" || row.Panic != "" {
			os.Exit(3)
		}
	}
}
