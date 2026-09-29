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

type batchInfo struct {
	ReceiveHeight uint64           `json:"receive_height"`
	Previous      types.HashHeight `json:"previous"`
	CommitHeights []uint64         `json:"commit_heights"`
}

// Build the children-before-receive layout used by VM.finalizeEmbedded, then
// use the node's transaction flattening and momentum-content constructor.
// This does not execute a VM or assert full-node transaction validity.
func writeContractBatchVectors() error {
	c := accountCorpus{FormatVersion: 1, Source: source{
		Repository: "https://github.com/zenon-network/go-zenon", Commit: nodeCommit,
		ModuleVersion: nodeVersion, ModuleSum: nodeSum,
	}}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // Public synthetic seed.
	user := types.PubKeyToAddress(key.Public().(ed25519.PublicKey))
	previousMomentum := types.NewHash([]byte("synthetic contract batch checkpoint"))
	c.Chain.Anchor = anchor{ChainID: 99, Height: 4000, Hash: previousMomentum.String()}
	ack := types.HashHeight{Hash: previousMomentum, Height: 4000}
	address := types.PillarContract
	segment := segmentVector{Name: "contract-batches", Address: hex.EncodeToString(address.Bytes()), RPCAddress: address.String()}
	previous, height := types.Hash{}, uint64(1)
	var blocks []*nom.AccountBlock
	for batch, size := range []int{2, 1} {
		children := make([]*nom.AccountBlock, 0, size)
		for child := range size {
			b := &nom.AccountBlock{
				Version: 1, ChainIdentifier: 99, BlockType: nom.BlockTypeContractSend,
				Address: address, Height: height, PreviousHash: previous, MomentumAcknowledged: ack,
				ToAddress: user, Amount: big.NewInt(int64(100 * (child + 1))), TokenStandard: types.ZnnTokenStandard,
				Data: []byte{byte(batch), byte(child), 255}, DescendantBlocks: []*nom.AccountBlock{},
			}
			b.Hash = b.ComputeHash()
			children = append(children, b)
			previous, height = b.Hash, height+1
		}
		receive := &nom.AccountBlock{
			Version: 1, ChainIdentifier: 99, BlockType: nom.BlockTypeContractReceive,
			Address: address, Height: height, PreviousHash: previous, MomentumAcknowledged: ack,
			FromBlockHash: types.NewHash([]byte(fmt.Sprintf("synthetic contract input %d", batch))),
			Amount:        big.NewInt(0), Data: make([]byte, 8), DescendantBlocks: children,
		}
		receive.Hash = receive.ComputeHash()
		info := batchInfo{ReceiveHeight: receive.Height, Previous: receive.Previous()}
		transaction := &nom.AccountBlockTransaction{Block: receive}
		for _, commit := range transaction.GetCommits() {
			b, ok := commit.(*nom.AccountBlock)
			if !ok {
				return fmt.Errorf("node returned an unexpected account commit type")
			}
			info.CommitHeights = append(info.CommitHeights, b.Height)
			blocks = append(blocks, b)
			segment.Vectors = append(segment.Vectors, accountVector{
				Name: fmt.Sprintf("contract-height-%d", b.Height), RPC: b, Block: expectedAccountBlock(b),
			})
		}
		c.Batches = append(c.Batches, info)
		previous, height = receive.Hash, height+1
	}
	c.Segments = []segmentVector{segment}
	for i := range 9 {
		m := baseMomentum()
		m.PreviousHash, m.Height = previousMomentum, c.Chain.Anchor.Height+1+uint64(i)
		m.TimestampUnix += uint64(i) * 10
		m.Data = []byte{0, byte(i), 255}
		if i == 2 {
			m.Content = nom.NewMomentumContent(blocks)
		}
		c.Chain.Vectors = append(c.Chain.Vectors, makeVector(fmt.Sprintf("contract-chain-%d", i+1), m, key))
		previousMomentum = m.Hash
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(c)
}
