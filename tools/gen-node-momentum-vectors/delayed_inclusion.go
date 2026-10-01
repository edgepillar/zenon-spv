package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common/types"
)

// Use the pinned node's hash, content-construction and RPC serialization paths.
// These are synthetic envelopes, not VM execution or node-accepted history.
func writeDelayedInclusionVectors() error {
	c := accountCorpus{FormatVersion: 1, Source: source{
		Repository: "https://github.com/zenon-network/go-zenon", Commit: nodeCommit,
		ModuleVersion: nodeVersion, ModuleSum: nodeSum,
	}}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // Public test seed.
	user := types.PubKeyToAddress(key.Public().(ed25519.PublicKey))
	previous := types.NewHash([]byte("synthetic delayed inclusion checkpoint"))
	c.Chain.Anchor = anchor{ChainID: 99, Height: 5000, Hash: previous.String()}
	c.Chain.V2FromHeight = 5009
	for _, entry := range []struct {
		name    string
		address types.Address
	}{{"user", user}, {"embedded", types.PillarContract}} {
		c.Segments = append(c.Segments, segmentVector{Name: entry.name,
			Address: hex.EncodeToString(entry.address.Bytes()), RPCAddress: entry.address.String()})
	}
	parents := [2]types.Hash{}
	accountHeight := uint64(0)
	for height := uint64(5001); height <= 5019; height++ {
		m := baseMomentum()
		m.PreviousHash, m.Height = previous, height
		m.TimestampUnix += (height - 5001) * 10
		m.Data = []byte{0, byte(height - 5000), 255}
		if height >= c.Chain.V2FromHeight {
			m.Version = 2
			m.NextFusionPrice, m.NextWorkPrice = 1000+(height-5009)*10, 1000+(height-5009)*20
		}
		if height == 5003 || height == 5007 || height == 5011 {
			accountHeight++
			ack := types.HashHeight{Hash: previous, Height: height - 1}
			send := &nom.AccountBlock{Version: 1, ChainIdentifier: 99, BlockType: nom.BlockTypeUserSend,
				Address: user, Height: accountHeight, PreviousHash: parents[0], MomentumAcknowledged: ack,
				ToAddress: types.PillarContract, Amount: big.NewInt(int64(accountHeight * 1000)),
				TokenStandard: types.ZnnTokenStandard, Data: []byte{byte(accountHeight), 255, 0},
				DescendantBlocks: []*nom.AccountBlock{}}
			send.Hash = send.ComputeHash()
			send.PublicKey, send.Signature = key.Public().(ed25519.PublicKey), ed25519.Sign(key, send.Hash.Bytes())
			receive := &nom.AccountBlock{Version: 1, ChainIdentifier: 99, BlockType: nom.BlockTypeContractReceive,
				Address: types.PillarContract, Height: accountHeight, PreviousHash: parents[1], MomentumAcknowledged: ack,
				FromBlockHash: send.Hash, Amount: big.NewInt(0), Data: []byte{}, DescendantBlocks: []*nom.AccountBlock{}}
			receive.Hash = receive.ComputeHash()
			blocks := []*nom.AccountBlock{send, receive}
			m.Content = nom.NewMomentumContent(blocks)
			for index, b := range blocks {
				c.Segments[index].Vectors = append(c.Segments[index].Vectors, accountVector{
					Name: fmt.Sprintf("%s-height-%d", c.Segments[index].Name, b.Height), RPC: b, Block: expectedAccountBlock(b)})
				parents[index] = b.Hash
			}
		}
		c.Chain.Vectors = append(c.Chain.Vectors, makeVector(fmt.Sprintf("delayed-chain-%d", height-5000), m, key))
		previous = m.Hash
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(c)
}
