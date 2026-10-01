// Command gen-node-momentum-vectors generates synthetic serialization vectors
// with the pinned node implementation. It does not import the SPV verifier.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"sort"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common/types"
)

const (
	nodeModule  = "github.com/zenon-network/go-zenon"
	nodeVersion = "v0.0.8-alphanet.0.20260924192459-3a4131e63881"
	nodeCommit  = "3a4131e63881058b6ce2ee81d3a41d0033fafc99"
	nodeSum     = "h1:7Yf9IL6y7T0gHnRrUs4oulsEcV6YXDRDiIKpUCurCHk="
)

// These DTOs deliberately use only node values and standard-library types.
// No expected hash, address, or wire representation comes from SPV code.
type expectedHeader struct {
	Version         uint64 `json:"version"`
	ChainIdentifier uint64 `json:"chainIdentifier"`
	Hash            string `json:"hash"`
	PreviousHash    string `json:"previousHash"`
	Height          uint64 `json:"height"`
	Timestamp       uint64 `json:"timestamp"`
	DataHash        string `json:"dataHash"`
	ContentHash     string `json:"contentHash"`
	ChangesHash     string `json:"changesHash"`
	PublicKey       []byte `json:"publicKey"`
	Signature       []byte `json:"signature"`
	NextFusionPrice uint64 `json:"nextFusionPrice"`
	NextWorkPrice   uint64 `json:"nextWorkPrice"`
}

type expectedContent struct {
	Address string `json:"address"`
	Height  uint64 `json:"height"`
	Hash    string `json:"hash"`
}

type vector struct {
	Name     string            `json:"name"`
	Momentum *nom.Momentum     `json:"momentum"`
	Header   expectedHeader    `json:"header"`
	Content  []expectedContent `json:"content"`
}

type source struct {
	Repository    string `json:"repository"`
	Commit        string `json:"commit"`
	ModuleVersion string `json:"module_version"`
	ModuleSum     string `json:"module_sum"`
}

type anchor struct {
	ChainID uint64 `json:"chain_id"`
	Height  uint64 `json:"height"`
	Hash    string `json:"header_hash"`
}

type corpus struct {
	FormatVersion int         `json:"format_version"`
	Source        source      `json:"source"`
	Vectors       []vector    `json:"vectors"`
	Chain         chainCorpus `json:"chain"`
	Transition    chainCorpus `json:"transition"`
}

type chainCorpus struct {
	Anchor       anchor   `json:"anchor"`
	V2FromHeight uint64   `json:"v2_from_height,omitempty"`
	Vectors      []vector `json:"vectors"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if err := checkNodePin(); err != nil {
		return err
	}
	if len(os.Args) > 1 {
		if len(os.Args) == 2 && os.Args[1] == "--account-amounts" {
			return writeAccountAmountVectors()
		}
		if len(os.Args) == 2 && os.Args[1] == "--account-segments" {
			return writeAccountSegmentVectors()
		}
		if len(os.Args) == 2 && os.Args[1] == "--contract-batches" {
			return writeContractBatchVectors()
		}
		if len(os.Args) == 2 && os.Args[1] == "--delayed-inclusion" {
			return writeDelayedInclusionVectors()
		}
		return fmt.Errorf("usage: gen-node-momentum-vectors [--account-amounts|--account-segments|--contract-batches|--delayed-inclusion]")
	}
	// Public, synthetic test key. Never use this all-zero seed for a wallet.
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	c := corpus{FormatVersion: 1, Source: source{
		Repository: "https://github.com/zenon-network/go-zenon",
		Commit:     nodeCommit, ModuleVersion: nodeVersion, ModuleSum: nodeSum,
	}}
	add := func(name string, edit func(*nom.Momentum)) {
		m := baseMomentum()
		edit(m)
		c.Vectors = append(c.Vectors, makeVector(name, m, key))
	}
	add("v1-empty", func(*nom.Momentum) {})
	add("v1-binary-data", func(m *nom.Momentum) { m.Data = []byte{0, 255, 128, 1, 0, 127} })
	add("v1-sorted-content", func(m *nom.Momentum) { m.Content = sampleContent() })
	add("v1-wide-integers", func(m *nom.Momentum) {
		m.ChainIdentifier = 1<<53 + 1
		m.Height = 1<<32 + 1
		m.TimestampUnix = 1<<53 + 3
		m.Content = sampleContent()
	})
	add("v1-max-integers", func(m *nom.Momentum) {
		m.ChainIdentifier, m.Height, m.TimestampUnix = ^uint64(0), ^uint64(0), ^uint64(0)
	})
	add("v1-price-fields-not-hashed", func(m *nom.Momentum) {
		m.NextFusionPrice, m.NextWorkPrice = 123, 456
	})
	add("v2-zero-prices", func(m *nom.Momentum) { m.Version = 2 })
	add("v2-nonzero-prices", func(m *nom.Momentum) {
		m.Version, m.NextFusionPrice, m.NextWorkPrice = 2, 1<<32+1, 1<<53+1
		m.Data, m.Content = []byte{255, 0, 128}, sampleContent()
	})
	add("v2-max-prices", func(m *nom.Momentum) {
		m.Version, m.NextFusionPrice, m.NextWorkPrice = 2, ^uint64(0), ^uint64(0)
	})
	previous := types.NewHash([]byte("synthetic momentum conformance checkpoint"))
	c.Chain.Anchor = anchor{ChainID: 99, Height: 1000, Hash: previous.String()}
	for i := range 6 {
		m := baseMomentum()
		m.PreviousHash, m.Height = previous, 1001+uint64(i)
		m.TimestampUnix += uint64(i) * 10
		m.Data, m.Content = []byte{0, byte(i), 255}, sampleContent()
		v := makeVector(fmt.Sprintf("v1-chain-%d", i+1), m, key)
		c.Chain.Vectors = append(c.Chain.Vectors, v)
		previous = m.Hash
	}
	previous = types.NewHash([]byte("synthetic v1-to-v2 checkpoint"))
	c.Transition.Anchor = anchor{ChainID: 99, Height: 2000, Hash: previous.String()}
	c.Transition.V2FromHeight = 2003
	for i := range 6 {
		m := baseMomentum()
		m.PreviousHash, m.Height = previous, 2001+uint64(i)
		m.TimestampUnix += uint64(i) * 10
		m.Content = sampleContent()
		if m.Height >= c.Transition.V2FromHeight {
			m.Version = 2
			m.NextFusionPrice, m.NextWorkPrice = 1000+uint64(i)*100, 1000+uint64(i)*200
		}
		v := makeVector(fmt.Sprintf("transition-%d", i+1), m, key)
		c.Transition.Vectors = append(c.Transition.Vectors, v)
		previous = m.Hash
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(c)
}

func baseMomentum() *nom.Momentum {
	return &nom.Momentum{
		Version: 1, ChainIdentifier: 99, Height: 1001, TimestampUnix: 1700000000,
		PreviousHash: types.NewHash([]byte("synthetic previous momentum")),
		ChangesHash:  types.NewHash([]byte("synthetic changes")),
		Data:         []byte{}, Content: nom.MomentumContent{},
	}
}

func sampleContent() nom.MomentumContent {
	// Deliberately supply unsorted input, including equal addresses/heights,
	// an embedded address, and values that expose integer byte order.
	user := types.PubKeyToAddress(ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey))
	content := nom.MomentumContent{
		{Address: types.PillarContract, HashHeight: types.HashHeight{Height: 1<<53 + 1, Hash: types.NewHash([]byte("embedded"))}},
		{Address: user, HashHeight: types.HashHeight{Height: 256, Hash: types.NewHash([]byte("user-high"))}},
		{Address: user, HashHeight: types.HashHeight{Height: 2, Hash: types.NewHash([]byte("user-low-b"))}},
		{Address: user, HashHeight: types.HashHeight{Height: 2, Hash: types.NewHash([]byte("user-low-a"))}},
	}
	// This is the node's own comparator, used by NewMomentumContent.
	sort.Slice(content, nom.AccountBlockHeaderComparer(content))
	return content
}

func makeVector(name string, m *nom.Momentum, key ed25519.PrivateKey) vector {
	m.Hash = m.ComputeHash()
	m.PublicKey = key.Public().(ed25519.PublicKey)
	m.Signature = ed25519.Sign(key, m.Hash.Bytes())
	content := make([]expectedContent, len(m.Content))
	for i, h := range m.Content {
		content[i] = expectedContent{Address: hex.EncodeToString(h.Address.Bytes()), Height: h.Height, Hash: h.Hash.String()}
	}
	return vector{Name: name, Momentum: m, Content: content, Header: expectedHeader{
		Version: m.Version, ChainIdentifier: m.ChainIdentifier, Hash: m.Hash.String(),
		PreviousHash: m.PreviousHash.String(), Height: m.Height, Timestamp: m.TimestampUnix,
		DataHash: types.NewHash(m.Data).String(), ContentHash: m.Content.Hash().String(),
		ChangesHash: m.ChangesHash.String(), PublicKey: m.PublicKey, Signature: m.Signature,
		NextFusionPrice: m.NextFusionPrice, NextWorkPrice: m.NextWorkPrice,
	}}
}

func checkNodePin() error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Errorf("missing build information; cannot verify node pin")
	}
	for _, dep := range info.Deps {
		if dep.Path == nodeModule {
			if dep.Version != nodeVersion || dep.Sum != nodeSum || dep.Replace != nil {
				return fmt.Errorf("node dependency differs from the declared corpus source")
			}
			return nil
		}
	}
	return fmt.Errorf("pinned node dependency not found")
}
