//go:build ignore

// SPDX-License-Identifier: MIT

// This standalone generator creates exactly four synthetic unit-test headers.
// Its public deterministic seed has no network, wallet or custody purpose.
// It does not start a node, register a domain, submit a batch or prove a state
// transition. Pass the separately captured three-leaf test root as one hex arg.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		panic("one synthetic root argument required")
	}
	root, err := hex.DecodeString(os.Args[1])
	if err != nil || len(root) != 32 {
		panic("32-byte synthetic root required")
	}
	seed := sha256.Sum256([]byte("zenon-spv public synthetic three-witness test key/v1"))
	key := ed25519.NewKeyFromSeed(seed[:])
	pub := key.Public().(ed25519.PublicKey)
	digest := sha3.Sum256(pub)
	address := append([]byte{0}, digest[:19]...)
	genesis := sha3.Sum256([]byte("zenon-spv synthetic three-witness genesis/v1"))
	anchor := sha3.Sum256([]byte("zenon-spv synthetic three-witness anchor/v1"))
	previous := anchor
	empty := sha3.Sum256(nil)
	changes := sha3.Sum256([]byte("synthetic opaque changes, no STF claim"))
	var projected, wire []map[string]any
	for height := uint64(87); height <= 90; height++ {
		var preimage bytes.Buffer
		word := func(n uint64) { var b [8]byte; binary.BigEndian.PutUint64(b[:], n); preimage.Write(b[:]) }
		word(3)
		word(9001)
		preimage.Write(previous[:])
		word(height)
		word(1700000000 + height)
		preimage.Write(empty[:])
		preimage.Write(empty[:])
		preimage.Write(changes[:])
		word(1000)
		word(1000)
		preimage.Write(root)
		if preimage.Len() != 208 {
			panic("synthetic preimage width")
		}
		hash := sha3.Sum256(preimage.Bytes())
		signature := ed25519.Sign(key, hash[:])
		if !ed25519.Verify(pub, hash[:], signature) {
			panic("synthetic signature self-check")
		}
		row := map[string]any{"version": 3, "chainIdentifier": 9001, "hash": hex.EncodeToString(hash[:]),
			"previousHash": hex.EncodeToString(previous[:]), "height": height, "timestamp": 1700000000 + height,
			"dataHash": hex.EncodeToString(empty[:]), "contentHash": hex.EncodeToString(empty[:]),
			"changesHash": hex.EncodeToString(changes[:]), "publicKey": []byte(pub), "signature": signature,
			"nextFusionPrice": 1000, "nextWorkPrice": 1000, "stateRoot": hex.EncodeToString(root)}
		projected = append(projected, row)
		raw := make(map[string]any, len(row)+1)
		for k, v := range row {
			raw[k] = v
		}
		delete(raw, "dataHash")
		delete(raw, "contentHash")
		raw["data"], raw["content"], raw["producer"] = []byte{}, []any{}, unitProducerAddress(address)
		wire = append(wire, raw)
		previous = hash
	}
	value := map[string]any{"scope": "SYNTHETIC_UNIT_HEADERS_NO_NETWORK_OR_STF_ACCEPTANCE", "chain_id": 9001,
		"genesis": hex.EncodeToString(genesis[:]), "anchor": hex.EncodeToString(anchor[:]),
		"producer": hex.EncodeToString(address), "projected": projected, "momentums": wire}
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fmt.Fprintln(os.Stderr, "cannot encode unit headers")
		os.Exit(1)
	}
}

// RPC producer fields use z1 Bech32, while local schedule entries use raw hex.
func unitProducerAddress(address []byte) string {
	if len(address) != 20 {
		panic("unit producer width")
	}
	var data []byte
	var acc uint32
	var bits uint
	for _, b := range address {
		acc = (acc << 8) | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			data = append(data, byte((acc>>bits)&31))
		}
	}
	values := append([]byte{byte('z') >> 5, 0, byte('z') & 31}, data...)
	values = append(values, make([]byte, 6)...)
	check := uint32(1)
	for _, v := range values {
		top := check >> 25
		check = ((check & 0x1ffffff) << 5) ^ uint32(v)
		for i, g := range [...]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3} {
			if (top>>uint(i))&1 != 0 {
				check ^= g
			}
		}
	}
	check ^= 1
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	out := []byte("z1")
	for _, v := range data {
		out = append(out, charset[v])
	}
	for i := 0; i < 6; i++ {
		out = append(out, charset[(check>>uint(5*(5-i)))&31])
	}
	return string(out)
}
