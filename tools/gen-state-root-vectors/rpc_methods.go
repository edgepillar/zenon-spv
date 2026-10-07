//go:build candidate_rpc

// SPDX-License-Identifier: GPL-3.0-only
// Execute actual read-only methods against recording synthetic chain/store stubs.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/zenon-network/go-zenon/chain"
	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/chain/store"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
	"github.com/zenon-network/go-zenon/rpc/api"
	"github.com/zenon-network/go-zenon/zenon"
)

func init() { rpcMethodGenerator = generateRPCMethods }

type rpcMethodInput struct {
	Name         string `json:"name"`
	Method       string `json:"method"`
	Height       uint64 `json:"height"`
	Version      uint64 `json:"version"`
	StoreHeight  uint64 `json:"store_height"`
	Missing      bool   `json:"missing_momentum"`
	HashOverride bool   `json:"hash_override"`
	KeyKind      string `json:"key_kind"`
	BindingName  string `json:"binding_name"`
	LookupError  string `json:"lookup_error"`
	ProofError   string `json:"proof_error"`
	RootError    string `json:"root_error"`
	ResponseKind string `json:"response_kind"`
}

type rpcMethodCase struct {
	Input      rpcMethodInput   `json:"input"`
	Momentum   any              `json:"momentum"`
	RequestKey *string          `json:"request_key_hex"`
	Trace      []map[string]any `json:"trace"`
	Result     string           `json:"result_json"`
	Error      any              `json:"error"`
}

type recordingRPCZenon struct {
	zenon.Zenon
	chain *recordingRPCChain
}

func (z *recordingRPCZenon) Chain() chain.Chain {
	z.chain.add(map[string]any{"method": "Zenon.Chain"})
	return z.chain
}

type recordingRPCStore struct {
	store.Momentum
	chain    *recordingRPCChain
	momentum *nom.Momentum
}

func (s *recordingRPCStore) GetMomentumByHeight(height uint64) (*nom.Momentum, error) {
	s.chain.add(map[string]any{"method": "MomentumStore.GetMomentumByHeight", "height": height})
	return s.momentum, s.chain.lookupErr
}

type recordingRPCChain struct {
	chain.Chain
	store                        *recordingRPCStore
	trace                        []map[string]any
	value, proof                 []byte
	root                         types.Hash
	lookupErr, proofErr, rootErr error
}

func (c *recordingRPCChain) add(row map[string]any) { c.trace = append(c.trace, row) }
func (c *recordingRPCChain) GetFrontierMomentumStore() store.Momentum {
	c.add(map[string]any{"method": "Chain.GetFrontierMomentumStore"})
	return c.store
}
func rpcIdentifier(id types.HashHeight) any {
	return map[string]any{"hash": id.Hash.String(), "height": id.Height}
}
func rpcOptionalHex(rawValue []byte) *string {
	if rawValue == nil {
		return nil
	}
	text := hx(rawValue)
	return &text
}
func (c *recordingRPCChain) GetProof(id types.HashHeight, key []byte) ([]byte, []byte, error) {
	c.add(map[string]any{"method": "Chain.GetProof", "identifier": rpcIdentifier(id), "key_hex": rpcOptionalHex(key)})
	return c.value, c.proof, c.proofErr
}
func (c *recordingRPCChain) StateRoot(id types.HashHeight) (types.Hash, error) {
	c.add(map[string]any{"method": "Chain.StateRoot", "identifier": rpcIdentifier(id)})
	if c.rootErr == chain.ErrStateTreeNotReady || (c.rootErr != nil && c.rootErr.Error() == "synthetic: no such version") {
		return types.ZeroHash, c.rootErr
	}
	return c.root, c.rootErr
}

func rpcStubError(kind string, code int) error {
	switch kind {
	case "":
		return nil
	case "not-ready":
		return chain.ErrStateTreeNotReady
	case "not-retained":
		return fmt.Errorf("synthetic: no such version")
	default:
		return common.NewErrorWCode(code, "synthetic "+kind+" failure")
	}
}
func rpcErrorResult(err error, c *recordingRPCChain) any {
	if err == nil {
		return nil
	}
	var code *int
	if coded, ok := err.(interface{ ErrorCode() int }); ok {
		n := coded.ErrorCode()
		code = &n
	}
	var identity *string
	for _, candidate := range []struct {
		name string
		err  error
	}{{"lookup", c.lookupErr}, {"proof", c.proofErr}, {"root", c.rootErr}} {
		if candidate.err != nil && err == candidate.err {
			name := candidate.name
			identity = &name
			break
		}
	}
	return map[string]any{"message": err.Error(), "code": code, "stub_error_identity": identity}
}

func rpcInputs() []rpcMethodInput {
	result := []rpcMethodInput{}
	for _, method := range []string{"GetProof", "GetStateRoot"} {
		for _, name := range []string{"zero-height", "lookup-error", "missing-momentum", "version-zero", "version-one", "version-two",
			"active-three", "version-four", "version-max", "store-height-diff", "store-hash-diff", "not-ready", "not-retained", "root-error", "coherent-root-substitution"} {
			item := rpcMethodInput{Name: method + "/" + name, Method: method, Height: 42, Version: 3, StoreHeight: 42, KeyKind: "balance", BindingName: "stored-zero", ResponseKind: "selected"}
			switch name {
			case "zero-height":
				item.Height = 0
			case "lookup-error":
				item.LookupError = "lookup"
			case "missing-momentum":
				item.Missing = true
			case "version-zero":
				item.Version = 0
			case "version-one":
				item.Version = 1
			case "version-two":
				item.Version = 2
			case "version-four":
				item.Version = 4
			case "version-max":
				item.Version = ^uint64(0)
			case "store-height-diff":
				item.StoreHeight = 43
			case "store-hash-diff":
				item.HashOverride = true
			case "not-ready":
				if method == "GetProof" {
					item.ProofError = name
				} else {
					item.RootError = name
				}
			case "not-retained":
				if method == "GetProof" {
					item.ProofError = name
				} else {
					item.RootError = name
				}
			case "root-error":
				item.RootError = "root"
			case "coherent-root-substitution":
				item.ResponseKind = "coherent-substitution"
			}
			result = append(result, item)
		}
	}
	for _, name := range []string{"present-one", "missing-token", "present-empty", "nil-key", "empty-key", "oversized-key",
		"nil-value-present-proof", "oversized-value", "proof-error-before-root-error", "root-substitution"} {
		item := rpcMethodInput{Name: "GetProof/" + name, Method: "GetProof", Height: 42, Version: 3, StoreHeight: 42, KeyKind: "balance", BindingName: "stored-zero", ResponseKind: "selected"}
		switch name {
		case "present-one":
			item.BindingName = "positive-one"
		case "missing-token":
			item.BindingName = "missing-token"
			item.KeyKind = "missing-token"
		case "present-empty":
			item.BindingName = "present-empty-core-only"
		case "nil-key":
			item.KeyKind = "nil"
		case "empty-key":
			item.KeyKind = "empty"
		case "oversized-key":
			item.KeyKind = "oversized"
		case "nil-value-present-proof":
			item.ResponseKind = "nil-value"
		case "oversized-value":
			item.ResponseKind = "oversized-value"
		case "proof-error-before-root-error":
			item.ProofError = "proof"
			item.RootError = "root"
		case "root-substitution":
			item.ResponseKind = "root-substitution"
		}
		result = append(result, item)
	}
	return result
}

func rpcLeafValue(name string) []byte {
	if name == "positive-one" {
		return raw(fmt.Sprintf("%064x", 1))
	}
	if name == "present-empty-core-only" {
		return []byte{}
	}
	return make([]byte, 32)
}
func rpcSelectedKey(kind string) []byte {
	switch kind {
	case "balance":
		return balanceKey(hx(bytes.Repeat([]byte{17}, 20)), hx(bytes.Repeat([]byte{34}, 10)))
	case "missing-token":
		return balanceKey(hx(bytes.Repeat([]byte{17}, 20)), hx(bytes.Repeat([]byte{68}, 10)))
	case "nil":
		return nil
	case "empty":
		return []byte{}
	case "oversized":
		return bytes.Repeat([]byte{119}, 1025)
	}
	panic("unknown synthetic RPC key kind")
}
func rpcPrimitive(key, value []byte) (types.Hash, []byte, []byte) {
	path := trie.Path(types.NewHash(rpcSelectedKey("balance")))
	paths, values := []trie.Path{path}, [][]byte{value}
	root, err := trie.RootOfLeaves(paths, values)
	if err != nil {
		panic(err)
	}
	_, observed, proof, err := trie.ProveByPath(paths, values, trie.Path(types.NewHash(key)))
	if err != nil {
		panic(err)
	}
	return root, observed, proof
}
func generateRPCMethods() any {
	cases := []rpcMethodCase{}
	for _, item := range rpcInputs() {
		key := rpcSelectedKey(item.KeyKind)
		selectedRoot, value, proof := rpcPrimitive(key, rpcLeafValue(item.BindingName))
		momentum := &nom.Momentum{Version: item.Version, ChainIdentifier: 2, PreviousHash: hash("5555555555555555555555555555555555555555555555555555555555555555"),
			Height: item.StoreHeight, TimestampUnix: 1700000000, ChangesHash: hash("6666666666666666666666666666666666666666666666666666666666666666"),
			NextFusionPrice: 7, NextWorkPrice: 11, StateRoot: selectedRoot}
		momentum.Hash = momentum.ComputeHash()
		if item.HashOverride {
			momentum.Hash = hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		}
		c := &recordingRPCChain{value: value, proof: proof, root: selectedRoot,
			lookupErr: rpcStubError(item.LookupError, -32101), proofErr: rpcStubError(item.ProofError, -32102), rootErr: rpcStubError(item.RootError, -32103)}
		switch item.ResponseKind {
		case "coherent-substitution":
			c.root, c.value, c.proof = rpcPrimitive(key, raw(fmt.Sprintf("%064x", 2)))
		case "nil-value":
			c.value = nil
		case "oversized-value":
			c.root, c.value, c.proof = rpcPrimitive(key, bytes.Repeat([]byte{119}, 4097))
		case "root-substitution":
			c.root = hash("4444444444444444444444444444444444444444444444444444444444444444")
		}
		c.store = &recordingRPCStore{chain: c, momentum: momentum}
		var selectedMomentum any = map[string]any{"version": momentum.Version, "height": momentum.Height, "hash": momentum.Hash.String(), "state_root": momentum.StateRoot.String()}
		if item.Missing {
			c.store.momentum = nil
			selectedMomentum = nil
		}
		actual := api.NewLedgerApi(&recordingRPCZenon{chain: c})
		var observed any
		var err error
		switch item.Method {
		case "GetProof":
			observed, err = actual.GetProof(item.Height, key)
		case "GetStateRoot":
			observed, err = actual.GetStateRoot(item.Height)
		default:
			panic("only explicitly selected read-only methods may run")
		}
		encoded, encodeErr := json.Marshal(observed)
		if encodeErr != nil {
			panic(encodeErr)
		}
		cases = append(cases, rpcMethodCase{Input: item, Momentum: selectedMomentum, RequestKey: rpcOptionalHex(key), Trace: c.trace,
			Result: string(encoded), Error: rpcErrorResult(err, c)})
	}
	return map[string]any{"format_version": 1, "kind": "candidate-rpc-method-research",
		"source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"scope": map[string]bool{"synthetic": true, "unsigned": true, "LedgerApi_constructor_executed": true, "LedgerApi_methods_executed": true,
			"recording_chain_store_stubs": true, "primitive_proof_api_executed": true, "StateProof_serializer_executed": true,
			"actual_chain_stateTree_executed": false, "rpc_dispatcher_executed": false, "rpc_transport_executed": false, "node_database_opened": false,
			"node_lifecycle_executed": false, "node_tests_executed": false, "profile_agreed": false, "network_activation_authenticated": false,
			"header_authentication_executed": false, "runtime_state_proof_acceptance": false}, "cases": cases}
}
