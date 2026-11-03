// SPDX-License-Identifier: MIT

package chain_test

import (
	"encoding/json"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// This replays a retained unsigned H1 projection. It does not reconstruct the
// genesis VM, run node managers or select a network trust root for consumers.
func selectedDevnetGenesisHeader(t *testing.T) chain.Header {
	t.Helper()
	raw := nodeBoundaryBytes(t, "internal/testdata/conformance/selected-devnet-genesis.json", 4027,
		"e11aa64274d4af0b6fd7995cf55ea2a49fdd4ca1ba6f8747acdde84467773805")
	nodeBoundaryBytes(t, "internal/testdata/conformance/selected-devnet-genesis-config.json", 8137,
		"0dd33b18b147f70b3d3d5f07199a2b45311f6e9b84a98b3f86d8f6c6b45f419a")
	nodeBoundaryBytes(t, "tools/gen-state-root-vectors/selected-devnet-genesis-lifecycle_test.go.txt", 4458,
		"1f2eb54d60b777ed73e6cebd1d1bcdff28a8a7536aa0f1617bad7fb36a3ee542")
	var recorded struct {
		Trace struct {
			Header chain.Header `json:"header"`
		} `json:"trace"`
	}
	if err := json.Unmarshal(raw, &recorded); err != nil {
		t.Fatal(err)
	}
	return recorded.Trace.Header
}

func TestCandidateV3HeaderSelectedDevnetGenesis(t *testing.T) {
	header := selectedDevnetGenesisHeader(t)
	want := candidateV3Hash(t, "fab7609bae7fd78eb7d2b0d4a5023832f1a6730921b862f2415da25524698dc9")
	if header.Version != 1 || header.ChainIdentifier != 69 || header.Height != 1 ||
		header.TimestampUnix != 1739923200 || !header.PreviousHash.IsZero() ||
		len(header.PublicKey) != 0 || len(header.Signature) != 0 ||
		header.NextFusionPrice != 0 || header.NextWorkPrice != 0 ||
		header.HeaderHash != want || header.ComputeHash() != want {
		t.Fatal("SPV v1 bytes differ from the selected source-genesis H1 capture")
	}
}

func TestCandidateV3HeaderSelectedDevnetGenesisFields(t *testing.T) {
	original := selectedDevnetGenesisHeader(t)
	for _, tc := range []struct {
		name   string
		change func(*chain.Header)
	}{
		{"version", func(h *chain.Header) { h.Version++ }},
		{"chain", func(h *chain.Header) { h.ChainIdentifier++ }},
		{"previous", func(h *chain.Header) { h.PreviousHash[0] ^= 1 }},
		{"height", func(h *chain.Header) { h.Height++ }},
		{"timestamp", func(h *chain.Header) { h.TimestampUnix++ }},
		{"data", func(h *chain.Header) { h.DataHash[0] ^= 1 }},
		{"content", func(h *chain.Header) { h.ContentHash[0] ^= 1 }},
		{"changes", func(h *chain.Header) { h.ChangesHash[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := original
			tc.change(&changed)
			if changed.ComputeHash() == original.HeaderHash {
				t.Fatal("changed unsigned H1 preimage matched the old source identity")
			}
		})
	}
	// Prices are not part of the v1 hash, even though the wire has these fields.
	changed := original
	changed.NextFusionPrice, changed.NextWorkPrice = 1, 2
	if changed.ComputeHash() != original.HeaderHash {
		t.Fatal("v1 source-genesis hash unexpectedly committed v2 prices")
	}
}
