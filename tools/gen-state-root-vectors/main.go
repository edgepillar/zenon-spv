// SPDX-License-Identifier: GPL-3.0-only
// Generate unsigned, synthetic candidate state-root byte fixtures with the
// separately verified node snapshot. No SPV implementation is imported.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"runtime/debug"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/trie"
	"github.com/zenon-network/go-zenon/common/types"
)

const nodeCommit = "56ce2c384966f2f1940967257a0788d3998a5eef"
const nodeTree = "d5abff528566a561e1a53a46103cb4b15ff63c6c"

type leaf struct {
	Path    string `json:"path"`
	Value   string `json:"value"`
	Address string `json:"address,omitempty"`
	Token   string `json:"token,omitempty"`
	Amount  string `json:"amount,omitempty"`
	RawKey  string `json:"raw_key,omitempty"`
}

type state struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Leaves []leaf `json:"leaves"`
	Root   string `json:"root"`
}

type proofCase struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	Domain     string `json:"domain"`
	Address    string `json:"address,omitempty"`
	Token      string `json:"token,omitempty"`
	RawKey     string `json:"raw_key,omitempty"`
	Path       string `json:"path"`
	Value      string `json:"value"`
	Present    bool   `json:"present"`
	Proof      string `json:"proof"`
	Root       string `json:"root"`
	NodeResult string `json:"node_result"`
}

type content struct {
	Address string `json:"address"`
	Height  uint64 `json:"height"`
	Hash    string `json:"hash"`
}

type fields struct {
	Version         uint64    `json:"version"`
	ChainIdentifier uint64    `json:"chain_identifier"`
	PreviousHash    string    `json:"previous_hash"`
	Height          uint64    `json:"height"`
	Timestamp       uint64    `json:"timestamp"`
	Data            string    `json:"data"`
	Content         []content `json:"content"`
	ChangesHash     string    `json:"changes_hash"`
	NextFusionPrice uint64    `json:"next_fusion_price"`
	NextWorkPrice   uint64    `json:"next_work_price"`
	StateRoot       string    `json:"state_root"`
}

type header struct {
	Name        string `json:"name"`
	Fields      fields `json:"fields"`
	DataHash    string `json:"data_hash"`
	ContentHash string `json:"content_hash"`
	Preimage    string `json:"preimage"`
	Hash        string `json:"hash"`
}

type corpus struct {
	FormatVersion int               `json:"format_version"`
	Kind          string            `json:"kind"`
	Source        map[string]string `json:"source"`
	Scope         map[string]bool   `json:"scope"`
	Headers       []header          `json:"headers"`
	States        []state           `json:"states"`
	Proofs        []proofCase       `json:"proofs"`
}

func raw(text string) []byte {
	b, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return b
}

func hash(text string) types.Hash { return types.BytesToHashPanic(raw(text)) }
func path(text string) trie.Path  { return trie.Path(hash(text)) }
func hx(value []byte) string      { return hex.EncodeToString(value) }

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func balanceKey(address, token string) []byte {
	a, t := raw(address), raw(token)
	require(len(a) == 20 && len(t) == 10, "invalid selected balance identity")
	return common.JoinBytes([]byte{3}, a, []byte{3}, t)
}

func makeState(name, kind string, leaves []leaf) state {
	paths, values := make([]trie.Path, len(leaves)), make([][]byte, len(leaves))
	for i, l := range leaves {
		paths[i], values[i] = path(l.Path), raw(l.Value)
	}
	root, err := trie.RootOfLeaves(paths, values)
	if err != nil {
		panic(err)
	}
	return state{Name: name, Kind: kind, Leaves: leaves, Root: root.String()}
}

func nodeResult(p proofCase) string {
	var ok bool
	var err error
	if p.Present {
		ok, err = trie.VerifyProofByPath(hash(p.Root), path(p.Path), raw(p.Value), raw(p.Proof))
	} else {
		ok, err = trie.VerifyAbsenceByPath(hash(p.Root), path(p.Path), raw(p.Proof))
	}
	switch {
	case errors.Is(err, trie.ErrProofMalformed):
		return "malformed"
	case errors.Is(err, trie.ErrProofPathMismatch):
		return "path_mismatch"
	case err != nil:
		panic(err)
	case ok:
		return "match"
	default:
		return "mismatch"
	}
}

func prove(s state, name, domain, selectedPath string) proofCase {
	paths, values := make([]trie.Path, len(s.Leaves)), make([][]byte, len(s.Leaves))
	for i, l := range s.Leaves {
		paths[i], values[i] = path(l.Path), raw(l.Value)
	}
	present, value, proof, err := trie.ProveByPath(paths, values, path(selectedPath))
	if err != nil {
		panic(err)
	}
	p := proofCase{Name: name, State: s.Name, Domain: domain, Path: selectedPath,
		Value: hx(value), Present: present, Proof: hx(proof), Root: s.Root}
	p.NodeResult = nodeResult(p)
	require(p.NodeResult == "match", "original node proof did not match")
	return p
}

func makeHeader(name string, m *nom.Momentum) header {
	dataHash, contentHash := types.NewHash(m.Data), m.Content.Hash()
	preimage := common.JoinBytes(common.Uint64ToBytes(m.Version), common.Uint64ToBytes(m.ChainIdentifier),
		m.PreviousHash.Bytes(), common.Uint64ToBytes(m.Height), common.Uint64ToBytes(m.TimestampUnix),
		dataHash.Bytes(), contentHash.Bytes(), m.ChangesHash.Bytes())
	if m.Version >= 2 {
		preimage = common.JoinBytes(preimage, common.Uint64ToBytes(m.NextFusionPrice), common.Uint64ToBytes(m.NextWorkPrice))
	}
	if m.Version >= 3 {
		preimage = common.JoinBytes(preimage, m.StateRoot.Bytes())
	}
	expected := m.ComputeHash()
	require(expected == types.NewHash(preimage), "node hash differs from its documented preimage")
	f := fields{Version: m.Version, ChainIdentifier: m.ChainIdentifier, PreviousHash: m.PreviousHash.String(),
		Height: m.Height, Timestamp: m.TimestampUnix, Data: hx(m.Data), Content: []content{},
		ChangesHash: m.ChangesHash.String(), NextFusionPrice: m.NextFusionPrice,
		NextWorkPrice: m.NextWorkPrice, StateRoot: m.StateRoot.String()}
	for _, c := range m.Content {
		f.Content = append(f.Content, content{Address: hx(c.Address.Bytes()), Height: c.Height, Hash: c.Hash.String()})
	}
	return header{Name: name, Fields: f, DataHash: dataHash.String(), ContentHash: contentHash.String(),
		Preimage: hx(preimage), Hash: expected.String()}
}

// Insert a stored zero sibling at an unused bitmap slot. The candidate decoder
// accepts this equivalent encoding even though its encoder omits zero siblings.
func withZeroSibling(proof []byte) []byte {
	require(len(proof) >= 99, "short proof")
	count := int(binary.BigEndian.Uint16(proof[97:99]))
	index, position := -1, 0
	for i := 0; i < 256; i++ {
		if proof[65+i/8]&(1<<uint(7-i%8)) == 0 {
			index = i
			break
		}
		position++
	}
	require(index >= 0, "proof has no unused sibling slot")
	offset := 99 + position*32
	out := common.JoinBytes(proof[:offset], make([]byte, 32), proof[offset:])
	out[65+index/8] |= 1 << uint(7-index%8)
	binary.BigEndian.PutUint16(out[97:99], uint16(count+1))
	return out
}

func generate() corpus {
	c := corpus{FormatVersion: 1, Kind: "candidate-state-root-byte-research",
		Source: map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit,
			"tree": nodeTree, "selection": "complete-source-snapshot-local-replacement"},
		Scope: map[string]bool{"synthetic": true, "unsigned": true, "candidate_primitive_execution": true,
			"network_activation_authenticated": false, "profile_agreed": false, "balance_maximum_pinned": false,
			"node_lifecycle_qualified": false, "runtime_state_proof_acceptance": false},
		Headers: []header{}, States: []state{}, Proofs: []proofCase{}}
	address := "000102030405060708090a0b0c0d0e0f10111213"
	tokens := []string{"0102030405060708090a", "0a090807060504030201", "1112131415161718191a", "2122232425262728292a"}
	amounts := []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), new(big.Int).Lsh(big.NewInt(1), 256)}
	names := []string{"stored-zero", "positive-one", "maximum-256-bit-magnitude", "257-bit-magnitude-only"}
	leaves := []leaf{}
	for i, amount := range amounts {
		key := balanceKey(address, tokens[i])
		leaves = append(leaves, leaf{Address: address, Token: tokens[i], Amount: amount.String(), RawKey: hx(key),
			Path: types.NewHash(key).String(), Value: hx(common.BigIntToBytes(amount))})
	}
	balances := makeState("synthetic-balance-magnitudes", "balance", leaves)
	c.States = append(c.States, balances)
	for i, l := range leaves {
		p := prove(balances, names[i], "balance", l.Path)
		p.Address, p.Token, p.RawKey = l.Address, l.Token, l.RawKey
		c.Proofs = append(c.Proofs, p)
	}
	for _, identity := range []struct{ name, a, t string }{
		{"missing-token", address, "ffffffffffffffffffff"},
		{"missing-address", "00131211100f0e0d0c0b0a090807060504030201", tokens[0]},
	} {
		key := balanceKey(identity.a, identity.t)
		p := prove(balances, identity.name, "balance", types.NewHash(key).String())
		p.Address, p.Token, p.RawKey = identity.a, identity.t, hx(key)
		c.Proofs = append(c.Proofs, p)
	}
	for _, excluded := range []struct {
		name string
		key  []byte
	}{
		{"excluded-plasma", common.JoinBytes([]byte{3}, raw(address), []byte{5})},
		{"excluded-frontier", common.JoinBytes([]byte{3}, raw(address), []byte{0})},
		{"excluded-mailbox", common.JoinBytes([]byte{4}, raw(address), []byte{0})},
		{"excluded-znn-index", common.JoinBytes([]byte{8}, raw(address))},
		{"storage-is-not-a-balance-query", common.JoinBytes([]byte{3}, raw(address), []byte{4, 0})},
	} {
		p := prove(balances, excluded.name, "excluded", types.NewHash(excluded.key).String())
		p.RawKey = hx(excluded.key)
		c.Proofs = append(c.Proofs, p)
	}
	zero := types.Hash{}.String()
	empty := makeState("empty-shared-core", "path_native", []leaf{})
	c.States = append(c.States, empty)
	c.Proofs = append(c.Proofs, prove(empty, "empty-tree-absence", "path_native", zero))
	presentEmpty := makeState("present-empty-shared-core", "path_native", []leaf{{Path: zero, Value: ""}})
	c.States = append(c.States, presentEmpty)
	c.Proofs = append(c.Proofs, prove(presentEmpty, "present-empty-core-only", "path_native", zero))
	branchLeaves := []leaf{{Path: zero, Value: "00"}}
	for i, depth := range []int{255, 248, 247, 7, 0} {
		var p types.Hash
		p[depth/8] = 1 << uint(7-depth%8)
		branchLeaves = append(branchLeaves, leaf{Path: p.String(), Value: hx([]byte{byte(i + 1), 0xff})})
	}
	branching := makeState("path-bit-and-bitmap-boundaries", "path_native", branchLeaves)
	c.States = append(c.States, branching)
	for i, l := range branchLeaves {
		c.Proofs = append(c.Proofs, prove(branching, fmt.Sprintf("branch-bit-%d", i), "path_native", l.Path))
	}
	var absentPath types.Hash
	absentPath[0], absentPath[31] = 0x80, 1
	c.Proofs = append(c.Proofs, prove(branching, "branch-boundary-absence", "path_native", absentPath.String()))
	maxLeaves := []leaf{}
	for depth := 0; depth < 256; depth++ {
		var p types.Hash
		p[depth/8] = 1 << uint(7-depth%8)
		maxLeaves = append(maxLeaves, leaf{Path: p.String(), Value: "ff"})
	}
	maxAbsent := makeState("256-sibling-absence", "path_native", maxLeaves)
	c.States = append(c.States, maxAbsent)
	c.Proofs = append(c.Proofs, prove(maxAbsent, "full-bitmap-absent-8291-bytes", "path_native", zero))
	maxPresent := makeState("256-sibling-presence", "path_native", append(append([]leaf{}, maxLeaves...), leaf{Path: zero, Value: zero}))
	c.States = append(c.States, maxPresent)
	c.Proofs = append(c.Proofs, prove(maxPresent, "full-bitmap-present-8327-bytes", "path_native", zero))
	base := c.Proofs[0]
	for _, p := range c.Proofs[:4] {
		if binary.BigEndian.Uint16(raw(p.Proof)[97:99]) > binary.BigEndian.Uint16(raw(base.Proof)[97:99]) {
			base = p
		}
	}
	require(binary.BigEndian.Uint16(raw(base.Proof)[97:99]) >= 2, "need distinct multiple siblings")
	mutate := func(name, wanted string, edit func(*proofCase, []byte) []byte) {
		p := base
		p.Name, p.Domain, p.Address, p.Token, p.RawKey = name, "path_native", "", "", ""
		p.Proof = hx(edit(&p, append([]byte{}, raw(base.Proof)...)))
		p.NodeResult = nodeResult(p)
		require(p.NodeResult == wanted, "non-vacuous mutation did not produce its expected node result: "+name)
		c.Proofs = append(c.Proofs, p)
	}
	mutate("wrong-root", "mismatch", func(p *proofCase, b []byte) []byte { r := raw(p.Root); r[0] ^= 1; p.Root = hx(r); return b })
	mutate("wrong-rpc-value", "mismatch", func(p *proofCase, b []byte) []byte { v := raw(p.Value); v[0] ^= 1; p.Value = hx(v); return b })
	mutate("wrong-selected-path", "path_mismatch", func(p *proofCase, b []byte) []byte { v := raw(p.Path); v[31] ^= 1; p.Path = hx(v); return b })
	mutate("double-hashed-selected-path", "path_mismatch", func(p *proofCase, b []byte) []byte { p.Path = types.NewHash(raw(p.Path)).String(); return b })
	mutate("reserved-flag", "malformed", func(_ *proofCase, b []byte) []byte { b[0] |= 2; return b })
	mutate("absence-flag-on-present-leaf", "malformed", func(_ *proofCase, b []byte) []byte { b[0] = 0; return b })
	mutate("truncated-value", "malformed", func(_ *proofCase, b []byte) []byte { return b[:len(b)-1] })
	mutate("trailing-byte", "malformed", func(_ *proofCase, b []byte) []byte { return append(b, 0) })
	mutate("little-endian-sibling-count", "malformed", func(_ *proofCase, b []byte) []byte { b[97], b[98] = b[98], b[97]; return b })
	mutate("bitmap-popcount-mismatch", "malformed", func(_ *proofCase, b []byte) []byte { b[98]++; return b })
	mutate("least-significant-first-bitmap", "mismatch", func(_ *proofCase, b []byte) []byte {
		before := append([]byte{}, b[65:97]...)
		for i := 65; i < 97; i++ {
			b[i] = bits.Reverse8(b[i])
		}
		require(!bytes.Equal(before, b[65:97]), "vacuous bitmap mutation")
		return b
	})
	mutate("reversed-sibling-order", "mismatch", func(_ *proofCase, b []byte) []byte {
		count := int(binary.BigEndian.Uint16(b[97:99]))
		old := append([]byte{}, b[99:99+count*32]...)
		for i := 0; i < count; i++ {
			copy(b[99+i*32:99+(i+1)*32], old[(count-1-i)*32:(count-i)*32])
		}
		require(!bytes.Equal(old, b[99:99+count*32]), "vacuous sibling-order mutation")
		return b
	})
	mutate("inconsistent-leaf-hash", "malformed", func(_ *proofCase, b []byte) []byte { b[33] ^= 1; return b })
	mutate("little-endian-value-length", "malformed", func(_ *proofCase, b []byte) []byte {
		off := 99 + int(binary.BigEndian.Uint16(b[97:99]))*32
		b[off], b[off+3] = b[off+3], b[off]
		b[off+1], b[off+2] = b[off+2], b[off+1]
		return b
	})
	mutate("present-proof-used-for-absence", "malformed", func(p *proofCase, b []byte) []byte { p.Present = false; return b })
	mutate("stored-zero-sibling-equivalent", "match", func(_ *proofCase, b []byte) []byte { return withZeroSibling(b) })
	absence := c.Proofs[4]
	for _, name := range []string{"nonzero-absent-leaf", "absence-proof-used-for-presence", "absent-stored-zero-sibling-equivalent"} {
		p := absence
		p.Name, p.Domain, p.Address, p.Token, p.RawKey = name, "path_native", "", "", ""
		b := raw(p.Proof)
		wanted := "malformed"
		switch name {
		case "nonzero-absent-leaf":
			b[33] = 1
		case "absence-proof-used-for-presence":
			p.Present = true
		default:
			b = withZeroSibling(b)
			wanted = "match"
		}
		p.Proof, p.NodeResult = hx(b), ""
		p.NodeResult = nodeResult(p)
		require(p.NodeResult == wanted, "absence mutation result mismatch")
		c.Proofs = append(c.Proofs, p)
	}
	addHeader := func(name string, edit func(*nom.Momentum)) {
		m := &nom.Momentum{Version: 3, ChainIdentifier: 99, PreviousHash: types.NewHash([]byte("synthetic state-root previous")),
			Height: 17, TimestampUnix: 1700000000, ChangesHash: types.NewHash([]byte("synthetic changes")),
			NextFusionPrice: 123, NextWorkPrice: 456, StateRoot: hash(balances.Root)}
		edit(m)
		c.Headers = append(c.Headers, makeHeader(name, m))
	}
	for _, version := range []uint64{1, 2} {
		addHeader(fmt.Sprintf("v%d-zero-root", version), func(m *nom.Momentum) { m.Version = version; m.StateRoot = types.Hash{} })
		addHeader(fmt.Sprintf("v%d-populated-root-ignored", version), func(m *nom.Momentum) { m.Version = version })
	}
	addHeader("v3-zero-root", func(m *nom.Momentum) { m.StateRoot = types.Hash{} })
	addHeader("v3-balance-root", func(_ *nom.Momentum) {})
	addHeader("v3-alternate-root", func(m *nom.Momentum) { m.StateRoot = types.NewHash([]byte("different synthetic root")) })
	addHeader("v3-binary-content", func(m *nom.Momentum) {
		m.Data = []byte{0, 255, 128, 1, 0, 127}
		for i, a := range []string{address, "00131211100f0e0d0c0b0a090807060504030201"} {
			var addr types.Address
			copy(addr[:], raw(a))
			m.Content = append(m.Content, &types.AccountHeader{Address: addr,
				HashHeight: types.HashHeight{Height: uint64(100 + i), Hash: types.NewHash([]byte{byte(i), 255})}})
		}
	})
	addHeader("v3-wide-integers", func(m *nom.Momentum) {
		m.ChainIdentifier = 1<<53 + 1
		m.Height = 1<<32 + 1
		m.TimestampUnix = 1<<53 + 3
		m.NextFusionPrice = 1<<32 + 1
		m.NextWorkPrice = 1<<53 + 1
	})
	addHeader("v3-maximum-integers", func(m *nom.Momentum) {
		m.ChainIdentifier = ^uint64(0)
		m.Height = ^uint64(0)
		m.TimestampUnix = ^uint64(0)
		m.NextFusionPrice = ^uint64(0)
		m.NextWorkPrice = ^uint64(0)
	})
	return c
}

type filterOperation struct {
	Kind  string `json:"kind"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

type filterRecording struct {
	operations []filterOperation
}

func (r *filterRecording) Put(key, value []byte) {
	r.operations = append(r.operations, filterOperation{"put", hx(key), hx(value)})
}

func (r *filterRecording) Delete(key []byte) {
	r.operations = append(r.operations, filterOperation{"delete", hx(key), ""})
}

type filterCase struct {
	Name   string            `json:"name"`
	Key    string            `json:"key"`
	Input  []filterOperation `json:"input"`
	Output []filterOperation `json:"output"`
}

func filterAccountKey(sub byte, tail []byte) []byte {
	return common.JoinBytes([]byte{3}, bytes.Repeat([]byte{17}, 20), []byte{sub}, tail)
}

func generateFilter() any {
	keys := []struct {
		name string
		key  []byte
	}{
		{"balance-32", filterAccountKey(3, bytes.Repeat([]byte{34}, 10))},
		{"storage", filterAccountKey(4, []byte{0, 255, 128})},
		{"balance-prefix-only-22", filterAccountKey(3, nil)},
		{"storage-prefix-only-22", filterAccountKey(4, nil)},
		{"balance-short-token-31", filterAccountKey(3, bytes.Repeat([]byte{34}, 9))},
		{"balance-long-token-33", filterAccountKey(3, bytes.Repeat([]byte{34}, 11))},
		{"empty", []byte{}},
		{"account-prefix", []byte{3}},
		{"partial-address", common.JoinBytes([]byte{3}, bytes.Repeat([]byte{17}, 10))},
		{"address-without-subprefix", common.JoinBytes([]byte{3}, bytes.Repeat([]byte{17}, 20))},
		{"account-subprefix-0", filterAccountKey(0, []byte{1})},
		{"account-subprefix-1", filterAccountKey(1, []byte{1})},
		{"account-subprefix-2", filterAccountKey(2, []byte{1})},
		{"account-subprefix-6", filterAccountKey(6, []byte{1})},
		{"account-subprefix-7", filterAccountKey(7, []byte{1})},
		{"momentum-history-0", []byte{0, 1}},
		{"momentum-history-1", []byte{1, 1}},
		{"momentum-history-2", []byte{2, 1}},
		{"momentum-history-5", []byte{5, 1}},
		{"momentum-history-9", []byte{9, 1}},
		{"mailbox", []byte{4, 1, 2}},
		{"znn-index", []byte{8, 1, 2}},
	}
	cases := make([]filterCase, 0, len(keys))
	for _, selected := range keys {
		patch := db.NewPatch()
		patch.Put(selected.key, bytes.Repeat([]byte{0}, 32))
		patch.Put(selected.key, []byte{})
		patch.Delete(selected.key)
		before := &filterRecording{operations: []filterOperation{}}
		after := &filterRecording{operations: []filterOperation{}}
		if err := patch.Replay(before); err != nil {
			panic(err)
		}
		if err := trie.FoldFilter(patch).Replay(after); err != nil {
			panic(err)
		}
		cases = append(cases, filterCase{selected.name, hx(selected.key), before.operations, after.operations})
	}
	return map[string]any{
		"format_version": 1,
		"kind":           "candidate-l1-fold-filter-research",
		"source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon",
			"revision": nodeCommit, "tree": nodeTree},
		"scope": map[string]bool{"synthetic": true, "unsigned": true,
			"l1_fold_filter_api_executed": true, "l1_staged_applier_executed": false,
			"node_database_opened": false, "node_lifecycle_executed": false,
			"node_tests_executed": false, "rpc_executed": false, "profile_agreed": false,
			"network_activation_authenticated": false, "runtime_state_proof_acceptance": false},
		"filter_cases": cases,
	}
}

type applierKey struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type applierObservation struct {
	Name       string `json:"name"`
	Key        string `json:"key"`
	Path       string `json:"path"`
	Value      string `json:"value"`
	Present    bool   `json:"present"`
	Proof      string `json:"proof"`
	NodeResult string `json:"node_result"`
}

type applierCheckpoint struct {
	Name         string               `json:"name"`
	Height       uint64               `json:"height"`
	Hash         string               `json:"hash"`
	Input        []filterOperation    `json:"input"`
	Root         string               `json:"root"`
	Observations []applierObservation `json:"observations"`
}

func generateApplier() any {
	// This opens a fresh, temporary in-memory database only. It exercises public
	// NodeTree APIs, not node startup, disk recovery, retention or a network.
	database, err := leveldb.Open(storage.NewMemStorage(), nil)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			panic(err)
		}
	}()
	tree, err := trie.NewNodeTree(database)
	if err != nil {
		panic(err)
	}
	keys := []applierKey{
		{"balance-a", hx(balanceKey(hx(bytes.Repeat([]byte{17}, 20)), hx(bytes.Repeat([]byte{34}, 10))))},
		{"balance-b", hx(balanceKey(hx(bytes.Repeat([]byte{51}, 20)), hx(bytes.Repeat([]byte{68}, 10))))},
		{"storage", hx(filterAccountKey(4, []byte{0, 255, 128}))},
		{"balance-prefix-only", hx(filterAccountKey(3, nil))},
		{"storage-prefix-only", hx(filterAccountKey(4, nil))},
		{"excluded-account-subprefix-0", hx(filterAccountKey(0, nil))},
		{"excluded-mailbox", hx([]byte{4, 1, 2})},
		{"excluded-znn-index", hx([]byte{8, 1, 2})},
	}
	checkpoints := []applierCheckpoint{}
	observe := func(name string, identifier types.HashHeight, input []filterOperation) {
		root, err := tree.Root(identifier)
		if err != nil {
			panic(err)
		}
		checkpoint := applierCheckpoint{Name: name, Height: identifier.Height, Hash: identifier.Hash.String(),
			Input: input, Root: root.String(), Observations: []applierObservation{}}
		for _, selected := range keys {
			key := raw(selected.Key)
			value, proof, err := tree.Prove(identifier, key)
			if err != nil {
				panic(err)
			}
			position := types.NewHash(key).String()
			p := proofCase{Root: root.String(), Path: position, Value: hx(value), Present: value != nil, Proof: hx(proof)}
			verdict := nodeResult(p)
			require(verdict == "match", "in-memory NodeTree proof does not match its root")
			checkpoint.Observations = append(checkpoint.Observations,
				applierObservation{selected.Name, selected.Key, position, hx(value), value != nil, hx(proof), verdict})
		}
		checkpoints = append(checkpoints, checkpoint)
	}
	observe("initial-empty", types.ZeroHashHeight, []filterOperation{})
	// Per-key event order is deliberate. Zero stays present, empty Put deletes,
	// and the last event wins among duplicate writes/deletes to the same path.
	steps := []struct {
		name   string
		values []int
	}{
		{"stored-zero", []int{0}},
		{"empty-then-overwrite", []int{-1, 1, 2}},
		{"delete-then-overwrite", []int{3, -2, 4}},
		{"empty-put-deletes", []int{-1}},
		{"restore-stored-zero", []int{0}},
		{"delete-wins", []int{1, -2}},
	}
	for index, step := range steps {
		patch := db.NewPatch()
		recorded := &filterRecording{operations: []filterOperation{}}
		for _, selected := range keys {
			key := raw(selected.Key)
			for _, number := range step.values {
				switch number {
				case -2:
					patch.Delete(key)
				case -1:
					patch.Put(key, []byte{})
				default:
					value := make([]byte, 32)
					value[31] = byte(number)
					patch.Put(key, value)
				}
			}
		}
		if err := patch.Replay(recorded); err != nil {
			panic(err)
		}
		if err := tree.Update(patch); err != nil {
			panic(err)
		}
		identifier := types.HashHeight{Height: uint64(index + 1),
			Hash: types.NewHash([]byte("synthetic-l1-applier-v1/" + step.name))}
		if err := tree.Commit(identifier); err != nil {
			panic(err)
		}
		require(tree.FrontierIdentifier() == identifier, "synthetic frontier differs after commit")
		observe(step.name, identifier, recorded.operations)
	}
	return map[string]any{
		"format_version": 1, "kind": "candidate-l1-applier-research", "backend": "NodeTree",
		"source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon",
			"revision": nodeCommit, "tree": nodeTree},
		"scope": map[string]bool{"synthetic": true, "unsigned": true,
			"l1_staged_applier_executed": true, "node_database_opened": true,
			"database_storage_in_memory_only": true, "temporary_database_closed": true,
			"persisted_disk_lifecycle_executed": false, "node_lifecycle_executed": false,
			"node_tests_executed": false, "rpc_executed": false, "profile_agreed": false,
			"network_activation_authenticated": false, "runtime_state_proof_acceptance": false},
		"selected_keys": keys, "checkpoints": checkpoints,
	}
}

// The optional candidate_wire build enables the actual RPC response serializer.
var wireGenerator func() any
var rpcMethodGenerator func() any
var rpcDispatcherGenerator func() any
var chainStartupGenerator func() any
var diskLifecycleGenerator func() any
var retentionResourceGenerator func() any
var bulkResourceGenerator func() any
var bulkGuardsGenerator func() any
var emptyVersionsGenerator func() any
var heightBoundaryGenerator func() any
var stagingBoundaryGenerator func() any
var patchDecodeGenerator func() any
var patchImportGenerator func() any
var patchTargetGenerator func() any
var patchResourceGenerator func() any

func run() error {
	// regenerate.py validates and copies every node blob before it builds this
	// separate module. Refuse an ordinary remote module or an unselected tree.
	if (len(os.Args) != 3 && len(os.Args) != 5) || os.Args[1] != "--verified-node-tree" || os.Args[2] != nodeTree {
		return fmt.Errorf("use the offline regenerate.py source-validation driver")
	}
	kind := "bytes"
	if len(os.Args) == 5 {
		kind = os.Args[4]
		if os.Args[3] != "--fixture-kind" || (kind != "fold-filter" && kind != "applier" && kind != "wire" && kind != "rpc-methods" && kind != "rpc-dispatcher" && kind != "chain-startup" && kind != "disk-lifecycle" && kind != "retention-resources" && kind != "bulk-tail" && kind != "bulk-guards" && kind != "empty-versions" && kind != "height-boundary" && kind != "staging-boundary" && kind != "patch-decode" && kind != "patch-import" && kind != "patch-targets" && kind != "patch-resources") {
			return fmt.Errorf("unsupported reference fixture kind")
		}
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Errorf("missing build provenance")
	}
	selected := false
	for _, dependency := range info.Deps {
		if dependency.Path == "github.com/zenon-network/go-zenon" {
			selected = dependency.Version == "v0.0.0" && dependency.Replace != nil &&
				dependency.Replace.Path == "../reference-node" &&
				(dependency.Replace.Version == "" || dependency.Replace.Version == "(devel)")
		}
	}
	if !selected {
		return fmt.Errorf("expected separately verified local candidate source")
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if kind == "fold-filter" {
		return encoder.Encode(generateFilter())
	}
	if kind == "applier" {
		return encoder.Encode(generateApplier())
	}
	if kind == "wire" {
		if wireGenerator == nil {
			return fmt.Errorf("wire mode requires the offline driver candidate_wire build")
		}
		return encoder.Encode(wireGenerator())
	}
	if kind == "rpc-methods" {
		if rpcMethodGenerator == nil {
			return fmt.Errorf("RPC method mode requires the offline driver candidate_rpc build")
		}
		return encoder.Encode(rpcMethodGenerator())
	}
	if kind == "rpc-dispatcher" {
		if rpcDispatcherGenerator == nil {
			return fmt.Errorf("RPC dispatcher mode requires the offline driver candidate_dispatcher build")
		}
		return encoder.Encode(rpcDispatcherGenerator())
	}
	if kind == "disk-lifecycle" {
		if diskLifecycleGenerator == nil {
			return fmt.Errorf("disk lifecycle mode requires the offline driver candidate_disk_lifecycle build")
		}
		return encoder.Encode(diskLifecycleGenerator())
	}
	if kind == "patch-resources" {
		if patchResourceGenerator == nil {
			return fmt.Errorf("patch resources requires the offline driver candidate_patch_import,candidate_patch_targets,candidate_patch_resources build on Linux or macOS")
		}
		return encoder.Encode(patchResourceGenerator())
	}
	if kind == "patch-targets" {
		if patchTargetGenerator == nil {
			return fmt.Errorf("patch targets mode requires the offline driver candidate_patch_import,candidate_patch_targets build")
		}
		return encoder.Encode(patchTargetGenerator())
	}
	if kind == "patch-import" {
		if patchImportGenerator == nil {
			return fmt.Errorf("patch import mode requires the offline driver candidate_patch_import build")
		}
		return encoder.Encode(patchImportGenerator())
	}
	if kind == "patch-decode" {
		if patchDecodeGenerator == nil {
			return fmt.Errorf("patch decode mode requires the offline driver candidate_patch_decode build")
		}
		return encoder.Encode(patchDecodeGenerator())
	}
	if kind == "staging-boundary" {
		if stagingBoundaryGenerator == nil {
			return fmt.Errorf("staging boundary mode requires the offline driver candidate_staging_boundary build")
		}
		return encoder.Encode(stagingBoundaryGenerator())
	}
	if kind == "height-boundary" {
		if heightBoundaryGenerator == nil {
			return fmt.Errorf("height-boundary generator unavailable")
		}
		return encoder.Encode(heightBoundaryGenerator())
	}

	if kind == "empty-versions" {
		if emptyVersionsGenerator == nil {
			return fmt.Errorf("empty version reference build tag required")
		}
		return encoder.Encode(emptyVersionsGenerator())
	}
	if kind == "bulk-guards" {
		if bulkGuardsGenerator == nil {
			return fmt.Errorf("bulk guard reference build tag required")
		}
		return encoder.Encode(bulkGuardsGenerator())
	}
	if kind == "bulk-tail" {
		if bulkResourceGenerator == nil {
			return fmt.Errorf("bulk tail mode requires the offline driver candidate_bulk_tail build on Linux or macOS")
		}
		return encoder.Encode(bulkResourceGenerator())
	}
	if kind == "retention-resources" {
		if retentionResourceGenerator == nil {
			return fmt.Errorf("retention resource mode requires the offline driver candidate_retention build on Linux or macOS")
		}
		return encoder.Encode(retentionResourceGenerator())
	}
	if kind == "chain-startup" {
		if chainStartupGenerator == nil {
			return fmt.Errorf("chain startup mode requires the offline driver candidate_chain_startup build")
		}
		return encoder.Encode(chainStartupGenerator())
	}
	return encoder.Encode(generate())
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
