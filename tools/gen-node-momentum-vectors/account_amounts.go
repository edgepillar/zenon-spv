package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/types"
)

// The node generates all expected bytes and hashes, including raw serialization
// of amounts its verifier would reject. No SPV implementation is imported.
func writeAccountAmountVectors() error {
	type amountVector struct {
		Name        string            `json:"name"`
		ScalarValid bool              `json:"scalar_valid"`
		AmountBytes string            `json:"amount_bytes"`
		RPC         *nom.AccountBlock `json:"rpc"`
		Block       map[string]any    `json:"block"`
	}
	corpus := struct {
		FormatVersion int            `json:"format_version"`
		Source        source         `json:"source"`
		Vectors       []amountVector `json:"vectors"`
	}{FormatVersion: 1, Source: source{
		Repository: "https://github.com/zenon-network/go-zenon", Commit: nodeCommit,
		ModuleVersion: nodeVersion, ModuleSum: nodeSum,
	}}
	power := func(bits uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), bits) }
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // Public synthetic test seed.
	for _, tc := range []struct {
		name   string
		amount *big.Int
		valid  bool
	}{
		{"zero", big.NewInt(0), true},
		{"ordinary", big.NewInt(1000), true},
		{"max-255-bits", new(big.Int).Sub(power(255), big.NewInt(1)), true},
		{"first-256-bit-value", power(255), false},
		{"overflow-alias", new(big.Int).Add(power(256), big.NewInt(1000)), false},
		{"wide-1025-bit-value", new(big.Int).Add(power(1024), big.NewInt(1000)), false},
		{"negative-alias", big.NewInt(-1000), false},
	} {
		b := &nom.AccountBlock{
			Version: 1, ChainIdentifier: 99, BlockType: nom.BlockTypeUserSend, Height: 42,
			PreviousHash:         types.NewHash([]byte("synthetic previous account block")),
			MomentumAcknowledged: types.HashHeight{Hash: types.NewHash([]byte("synthetic acknowledged momentum")), Height: 1000},
			Address:              types.PubKeyToAddress(key.Public().(ed25519.PublicKey)), ToAddress: types.PillarContract,
			Amount: tc.amount, TokenStandard: types.ZnnTokenStandard, Data: []byte{0, 255, 1},
			FusedPlasma: 1<<32 + 1, Difficulty: 1<<53 + 1, Nonce: nom.Nonce{Data: [8]byte{1, 2, 3}},
			DescendantBlocks: []*nom.AccountBlock{{Hash: types.NewHash([]byte("synthetic descendant")), Amount: big.NewInt(0)}},
		}
		b.Hash = b.ComputeHash()
		b.PublicKey = key.Public().(ed25519.PublicKey)
		b.Signature = ed25519.Sign(key, b.Hash.Bytes())
		block := expectedAccountBlock(b)
		corpus.Vectors = append(corpus.Vectors, amountVector{tc.name, tc.valid, hex.EncodeToString(common.BigIntToBytes(tc.amount)), b, block})
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(corpus)
}

func expectedAccountBlock(b *nom.AccountBlock) map[string]any {
	return map[string]any{
		"version": b.Version, "chainIdentifier": b.ChainIdentifier, "blockType": b.BlockType,
		"previousHash": b.PreviousHash.String(), "height": b.Height, "momentumAcknowledged": b.MomentumAcknowledged,
		"address": hex.EncodeToString(b.Address.Bytes()), "toAddress": hex.EncodeToString(b.ToAddress.Bytes()),
		"amount": json.Number(b.Amount.String()), "tokenStandard": hex.EncodeToString(b.TokenStandard.Bytes()),
		"fromBlockHash": b.FromBlockHash.String(), "descendantBlocksHash": b.DescendantBlocksHash().String(),
		"dataHash": types.NewHash(b.Data).String(), "fusedPlasma": b.FusedPlasma, "difficulty": b.Difficulty,
		"nonce": hex.EncodeToString(b.Nonce.Data[:]), "hash": b.Hash.String(), "publicKey": b.PublicKey, "signature": b.Signature,
	}
}
