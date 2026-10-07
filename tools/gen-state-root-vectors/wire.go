//go:build candidate_wire

// SPDX-License-Identifier: GPL-3.0-only
// This optional serializer mode imports the complete reference RPC package.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
	"github.com/zenon-network/go-zenon/rpc/api"
)

func init() { wireGenerator = generateWire }

type wireCase struct {
	Name  string  `json:"name"`
	Value *string `json:"value_hex"`
	Proof *string `json:"proof_hex"`
	Root  string  `json:"root"`
	JSON  string  `json:"wire"`
}

type wireBindingCase struct {
	wireCase
	RawKey     string `json:"raw_key"`
	Path       string `json:"path"`
	Present    bool   `json:"present"`
	NodeResult string `json:"node_result"`
}

func optionalHex(value []byte) *string {
	if value == nil {
		return nil
	}
	text := hx(value)
	return &text
}

func serializeStateProof(name string, value, proof []byte, root types.Hash) wireCase {
	// Serialize the actual pinned RPC response type. No LedgerApi constructor,
	// method, RPC transport or database is used by this mode.
	encoded, err := json.Marshal(&api.StateProof{Value: value, Proof: proof, Root: root})
	if err != nil {
		panic(err)
	}
	return wireCase{Name: name, Value: optionalHex(value), Proof: optionalHex(proof),
		Root: root.String(), JSON: string(encoded)}
}

func generateWire() any {
	ascending, descending := make([]byte, 256), make([]byte, 256)
	for index := range ascending {
		ascending[index], descending[index] = byte(index), byte(255-index)
	}
	serialization := []wireCase{
		serializeStateProof("nil-nil", nil, nil, types.ZeroHash),
		serializeStateProof("empty-empty", []byte{}, []byte{}, types.BytesToHashPanic(ascending[:32])),
		serializeStateProof("nil-empty", nil, []byte{}, hash(fmt.Sprintf("%064x", 17))),
		serializeStateProof("empty-nil", []byte{}, nil, types.BytesToHashPanic(bytes.Repeat([]byte{255}, 32))),
		serializeStateProof("base64-padding", []byte{251}, []byte{255, 0}, types.BytesToHashPanic(bytes.Repeat([]byte{170}, 32))),
		serializeStateProof("binary-range", ascending, descending, types.NewHash([]byte("synthetic-state-proof-wire-v1"))),
		serializeStateProof("stored-zero-bytes", make([]byte, 32), []byte{0, 255, 128, 1}, types.BytesToHashPanic(bytes.Repeat([]byte{34}, 32))),
	}
	address, token := hx(bytes.Repeat([]byte{17}, 20)), hx(bytes.Repeat([]byte{34}, 10))
	key := balanceKey(address, token)
	selected := []struct {
		name  string
		key   []byte
		value []byte
	}{
		{"stored-zero", key, make([]byte, 32)},
		{"positive-one", key, raw(fmt.Sprintf("%064x", 1))},
		{"missing-token", balanceKey(address, hx(bytes.Repeat([]byte{68}, 10))), make([]byte, 32)},
		{"missing-address", balanceKey(hx(bytes.Repeat([]byte{51}, 20)), token), make([]byte, 32)},
		{"excluded-mailbox", []byte{4, 1, 2}, make([]byte, 32)},
		{"storage-is-not-a-balance", common.JoinBytes([]byte{3}, raw(address), []byte{4, 0, 255, 128}), make([]byte, 32)},
		{"present-empty-core-only", key, []byte{}},
	}
	bindings := []wireBindingCase{}
	for _, item := range selected {
		paths, values := []trie.Path{trie.Path(types.NewHash(key))}, [][]byte{item.value}
		root, err := trie.RootOfLeaves(paths, values)
		if err != nil {
			panic(err)
		}
		selectedPath := trie.Path(types.NewHash(item.key))
		present, value, proof, err := trie.ProveByPath(paths, values, selectedPath)
		if err != nil {
			panic(err)
		}
		p := proofCase{Root: root.String(), Path: types.Hash(selectedPath).String(),
			Value: hx(value), Proof: hx(proof), Present: present}
		verdict := nodeResult(p)
		require(verdict == "match", "wire reference proof does not match")
		bindings = append(bindings, wireBindingCase{wireCase: serializeStateProof(item.name, value, proof, root),
			RawKey: hx(item.key), Path: p.Path, Present: present, NodeResult: verdict})
	}
	return map[string]any{
		"format_version": 1, "kind": "candidate-state-proof-wire-research",
		"source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"scope": map[string]bool{"synthetic": true, "unsigned": true, "StateProof_serializer_executed": true,
			"primitive_proof_api_executed": true, "LedgerApi_method_executed": false, "rpc_transport_executed": false,
			"node_database_opened": false, "l1_staged_applier_executed": false, "node_lifecycle_executed": false,
			"node_tests_executed": false, "profile_agreed": false, "network_activation_authenticated": false,
			"header_authentication_executed": false, "runtime_state_proof_acceptance": false},
		"serialization_cases": serialization, "binding_cases": bindings,
	}
}
