package conformance_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type historicalGenesisCorpus struct {
	FormatVersion int `json:"format_version"`
	Source        struct {
		Repository    string `json:"repository"`
		Commit        string `json:"commit"`
		ModuleVersion string `json:"module_version"`
		ModuleSum     string `json:"module_sum"`
	} `json:"source"`
	GenesisConfig struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Path       string `json:"path"`
		SHA256     string `json:"sha256"`
	} `json:"genesis_config"`
	Anchor verify.GenesisTrustRoot `json:"anchor"`
	Vector momentumVector          `json:"vector"`
}

func loadHistoricalGenesisCorpus(t testing.TB) historicalGenesisCorpus {
	t.Helper()
	raw, err := os.ReadFile("../testdata/conformance/historical-testnet-genesis.json")
	if err != nil {
		t.Fatal("cannot read the node-derived historical genesis corpus")
	}
	var c historicalGenesisCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal("cannot decode the node-derived historical genesis corpus")
	}
	if c.FormatVersion != 1 || c.Source.Repository != "https://github.com/zenon-network/go-zenon" ||
		c.Source.Commit != "3a4131e63881058b6ce2ee81d3a41d0033fafc99" ||
		c.Source.ModuleVersion != "v0.0.8-alphanet.0.20260924192459-3a4131e63881" ||
		c.Source.ModuleSum != "h1:7Yf9IL6y7T0gHnRrUs4oulsEcV6YXDRDiIKpUCurCHk=" ||
		c.GenesisConfig.Repository != "https://github.com/HyperCore-Team/dockerized-testnet" ||
		c.GenesisConfig.Commit != "a8db3e7e42718fc025e604dcb45e4690fd2f3d7a" ||
		c.GenesisConfig.Path != "data/configs/genesis.json" ||
		c.GenesisConfig.SHA256 != "a293ee85c4273e5119f18e23f5929f8382981be904109b53070f0fe6a89e1240" {
		t.Fatal("unexpected historical genesis format or source identities")
	}
	if c.Vector.Name != "historical-testnet-genesis" || len(c.Vector.Momentum) == 0 || len(c.Vector.Content) != 47 ||
		c.Anchor.ChainID != 3 || c.Anchor.Height != 1 || c.Anchor.HeaderHash.IsZero() ||
		c.Vector.Header.ChainIdentifier != c.Anchor.ChainID || c.Vector.Header.Height != c.Anchor.Height ||
		c.Vector.Header.HeaderHash != c.Anchor.HeaderHash || c.Vector.Header.Version != 1 ||
		c.Vector.Header.TimestampUnix != 1666083600 ||
		!c.Vector.Header.PreviousHash.IsZero() || len(c.Vector.Header.PublicKey) != 0 || len(c.Vector.Header.Signature) != 0 {
		t.Fatal("incomplete or unexpected unsigned historical genesis")
	}
	return c
}

func TestNodeHistoricalTestnetGenesis(t *testing.T) {
	c := loadHistoricalGenesisCorpus(t)
	// This is offline compatibility of the pinned node with an unchanged
	// historical configuration. It proves no current network, independently
	// trusted anchor, activation or finality.
	t.Run("node_hashes", func(t *testing.T) {
		if c.Vector.Header.ComputeHash() != c.Vector.Header.HeaderHash ||
			chain.MomentumContentHash(c.Vector.Content) != c.Vector.Header.ContentHash {
			t.Fatal("historical genesis hashes differ from the node-produced values")
		}
		var wire struct {
			Data string `json:"data"`
		}
		if err := json.Unmarshal(c.Vector.Momentum, &wire); err != nil {
			t.Fatal("cannot decode node-produced genesis data")
		}
		data, err := base64.StdEncoding.DecodeString(wire.Data)
		if err != nil || len(data) != 0 || sha3.Sum256(data) != c.Vector.Header.DataHash {
			t.Fatal("historical genesis data differs from the node-produced value")
		}
	})
	t.Run("node_rpc_conversion", func(t *testing.T) {
		got, err := fetchVectors(t, []momentumVector{c.Vector})
		if err != nil || len(got) != 1 {
			t.Fatal("cannot decode the node-produced genesis RPC response")
		}
		if len(got[0].Header.PublicKey) != 0 || len(got[0].Header.Signature) != 0 {
			t.Fatal("unsigned node genesis gained a signed envelope")
		}
		want := c.Vector.Header
		// The node JSON can represent an absent byte slice as either null or
		// an empty string; both are the same unsigned envelope here.
		got[0].Header.PublicKey, got[0].Header.Signature = nil, nil
		want.PublicKey, want.Signature = nil, nil
		if !reflect.DeepEqual(got[0].Header, want) || !slices.Equal(got[0].Content, c.Vector.Content) {
			t.Fatal("genesis RPC conversion differs from the node header or content order")
		}
	})
}
