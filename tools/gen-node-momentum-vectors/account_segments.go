package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common/types"
)

// These linked serialization fixtures do not execute account transactions or
// claim that a node would accept the synthetic momentum/account sequences.
func writeAccountSegmentVectors() error {
	type accountVector struct {
		Name  string            `json:"name"`
		RPC   *nom.AccountBlock `json:"rpc"`
		Block map[string]any    `json:"block"`
	}
	type segmentVector struct {
		Name       string          `json:"name"`
		Address    string          `json:"address"`
		RPCAddress string          `json:"rpc_address"`
		Vectors    []accountVector `json:"vectors"`
	}
	c := struct {
		FormatVersion int             `json:"format_version"`
		Source        source          `json:"source"`
		Chain         chainCorpus     `json:"chain"`
		Segments      []segmentVector `json:"segments"`
	}{FormatVersion: 1, Source: source{
		Repository: "https://github.com/zenon-network/go-zenon", Commit: nodeCommit,
		ModuleVersion: nodeVersion, ModuleSum: nodeSum,
	}}
	// The same public all-zero test seed as the other corpora, never a wallet key.
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	user := types.PubKeyToAddress(key.Public().(ed25519.PublicKey))
	previous := types.NewHash([]byte("synthetic account segment checkpoint"))
	c.Chain.Anchor = anchor{ChainID: 99, Height: 3000, Hash: previous.String()}
	ack := types.HashHeight{Hash: previous, Height: c.Chain.Anchor.Height}
	makeBlock := func(kind, height uint64, address types.Address, parent types.Hash) *nom.AccountBlock {
		return &nom.AccountBlock{
			Version: 1, ChainIdentifier: 99, BlockType: kind, Height: height,
			Address: address, PreviousHash: parent, MomentumAcknowledged: ack,
			Amount: big.NewInt(0), Data: []byte{}, DescendantBlocks: []*nom.AccountBlock{},
		}
	}
	seal := func(b *nom.AccountBlock) {
		b.Hash = b.ComputeHash()
		if !types.IsEmbeddedAddress(b.Address) {
			b.PublicKey = key.Public().(ed25519.PublicKey)
			b.Signature = ed25519.Sign(key, b.Hash.Bytes())
		}
	}
	userSend := makeBlock(nom.BlockTypeUserSend, 1, user, types.Hash{})
	userSend.ToAddress, userSend.Amount, userSend.TokenStandard = types.PillarContract, big.NewInt(1000), types.ZnnTokenStandard
	userSend.Data = []byte{0, 255, 128, 1}
	seal(userSend)
	contractReceive := makeBlock(nom.BlockTypeContractReceive, 1, types.PillarContract, types.Hash{})
	contractReceive.FromBlockHash = userSend.Hash
	seal(contractReceive)
	contractSend := makeBlock(nom.BlockTypeContractSend, 2, types.PillarContract, contractReceive.Hash)
	contractSend.ToAddress, contractSend.Amount, contractSend.TokenStandard = user, big.NewInt(1000), types.ZnnTokenStandard
	seal(contractSend)
	userReceive := makeBlock(nom.BlockTypeUserReceive, 2, user, userSend.Hash)
	userReceive.FromBlockHash = contractSend.Hash
	seal(userReceive)
	content := nom.MomentumContent{}
	for _, entry := range []struct {
		name   string
		blocks []*nom.AccountBlock
	}{
		{"user", []*nom.AccountBlock{userSend, userReceive}},
		{"embedded", []*nom.AccountBlock{contractReceive, contractSend}},
	} {
		address := entry.blocks[0].Address
		segment := segmentVector{Name: entry.name, Address: hex.EncodeToString(address.Bytes()), RPCAddress: address.String()}
		for _, b := range entry.blocks {
			segment.Vectors = append(segment.Vectors, accountVector{
				Name: fmt.Sprintf("%s-type-%d", entry.name, b.BlockType), RPC: b, Block: expectedAccountBlock(b),
			})
			header := b.Header()
			content = append(content, &header)
		}
		c.Segments = append(c.Segments, segment)
	}
	sort.Slice(content, nom.AccountBlockHeaderComparer(content))
	for i := range 9 {
		m := baseMomentum()
		m.PreviousHash, m.Height = previous, c.Chain.Anchor.Height+1+uint64(i)
		m.TimestampUnix += uint64(i) * 10
		m.Data = []byte{0, byte(i), 255}
		if i == 2 {
			m.Content = content // six verified headers follow this commitment
		}
		c.Chain.Vectors = append(c.Chain.Vectors, makeVector(fmt.Sprintf("account-chain-%d", i+1), m, key))
		previous = m.Hash
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(c)
}
