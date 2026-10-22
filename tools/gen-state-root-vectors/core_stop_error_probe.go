//go:build candidate_core_stop_errors

// SPDX-License-Identifier: GPL-3.0-only
// Observe genuine owned-handle close errors during finite core-manager shutdown.
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
	"path/filepath"

	"github.com/inconshreveable/log15"
	"github.com/syndtr/goleveldb/leveldb"
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
	Error       string   `json:"error"`
	Panic       string   `json:"panic"`
	ClosedError bool     `json:"closed_error"`
	LeafClasses []string `json:"leaf_classes"`
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
func stopLeaves(err error) []string {
	if err == nil {
		return []string{}
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		result := []string{}
		for _, child := range joined.Unwrap() {
			result = append(result, stopLeaves(child)...)
		}
		return result
	}
	if errors.Is(err, leveldb.ErrClosed) {
		return []string{"leveldb-closed"}
	}
	return []string{"other:" + err.Error()}
}
func stop(v zenon.Zenon) (out callResult) {
	out.LeafClasses = []string{}
	defer func() {
		if p := recover(); p != nil {
			out.Panic = fmt.Sprint(p)
		}
	}()
	if err := v.Stop(); err != nil {
		out.Error = err.Error()
		out.ClosedError = errors.Is(err, leveldb.ErrClosed)
		out.LeafClasses = stopLeaves(err)
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
	root := flag.String("root", "", "caller-owned empty case directory")
	input := flag.String("selection", "", "sealed source-genesis selection")
	inputSHA := flag.String("selection-sha256", "", "sealed selection digest")
	flag.Parse()
	if flag.NArg() != 0 || (*mode != "healthy" && *mode != "cache-closed" && *mode != "both-closed") {
		panic("unselected case")
	}
	info, err := os.Lstat(*input)
	must(err)
	if !info.Mode().IsRegular() || info.Size() > 8192 {
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
	if len(entries) != 0 {
		panic("fresh owned root required")
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
	z, err := zenon.NewZenon(&zenon.Config{MinPeers: 1, MinConnectedPeers: 1, DataDir: *root,
		GenesisConfig: g, ProducingKeyPair: nil, StateTreeArchive: false})
	must(err)
	if z.Config().ProducingKeyPair != nil || z.Producer().GetCoinBase() != nil {
		panic("keyless selection")
	}
	must(z.Init())
	before := query(z, chosen, key)
	consensusBefore := zenon.CandidateCoreStopConsensusStatus(z)
	faults := []string{}
	if *mode != "healthy" {
		must(zenon.CandidateCoreStopCloseCacheHandle(z))
		faults = append(faults, "cache-handle")
	}
	if *mode == "both-closed" {
		must(zenon.CandidateCoreStopCloseConsensusHandle(z))
		faults = append(faults, "consensus-handle")
	}
	consensusAfterFault := zenon.CandidateCoreStopConsensusStatus(z)
	observed := stop(z)
	after := query(z, chosen, key)
	consensusAfter := zenon.CandidateCoreStopConsensusStatus(z)
	callerTeardown := []string{}
	if consensusAfter == "open" {
		must(zenon.CandidateCoreStopCloseConsensusHandle(z))
		callerTeardown = append(callerTeardown, "consensus-handle")
	}
	finalConsensus := zenon.CandidateCoreStopConsensusStatus(z)
	reopened, err := leveldb.OpenFile(filepath.Join(*root, "consensus"), nil)
	must(err)
	must(reopened.Close())
	report := map[string]any{
		"schema": "zenon-core-stop-error-observation-v1", "case": *mode,
		"selection_sha256": *inputSHA, "genesis_identifier": chosen.Genesis,
		"genesis_patch_bytes": len(patch), "genesis_patch_sha256": hex.EncodeToString(patchHash[:]),
		"initialized": true, "core_started": false, "before_stop": before, "stop": observed,
		"after_stop": after, "controlled_closed_handles": faults,
		"consensus_before_fault": consensusBefore, "consensus_after_fault": consensusAfterFault,
		"consensus_after_stop": consensusAfter, "caller_teardown_after_observation": callerTeardown,
		"final_consensus_status": finalConsensus, "consensus_reopened_after_teardown": true,
		"final_tree_ready":         z.Chain().StateTreeReady(),
		"producing_key_configured": false, "wallet_manager_created": false,
		"node_wrapper_created": false, "p2p_server_created": false, "RPC_listener_started": false,
		"external_peer_configured": false, "production_state_value_accepted": false,
		"header_authentication_executed": false, "consumer_result": "REFUSED",
	}
	must(json.NewEncoder(output).Encode(report))
	fmt.Fprintln(os.Stderr, "ZENON_CORE_STOP_ERROR_PROCESS_COMPLETE")
	if observed.Panic != "" || finalConsensus != "closed" || z.Chain().StateTreeReady() {
		os.Exit(2)
	}
}
