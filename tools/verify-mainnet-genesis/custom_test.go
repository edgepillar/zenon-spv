package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/verify"
)

// Recompute both the observation and its explicit pin so rejection exercises
// the genesis shape boundary rather than a stale or inconsistent wire hash.
// Successful custom observations are covered by the independent node corpus.
func TestCustomGenesisRejectsConsistentNonGenesisShape(t *testing.T) {
	for _, name := range []string{"chain", "layout", "previous_hash"} {
		t.Run(name, func(t *testing.T) {
			h := genesisFixture()
			h.ChainIdentifier = 3
			switch name {
			case "chain":
				h.ChainIdentifier = 99
			case "layout":
				h.Version, h.NextFusionPrice, h.NextWorkPrice = 2, 1000, 1000
			case "previous_hash":
				h.PreviousHash[0] = 1
			}
			h.HeaderHash = h.ComputeHash()
			anchor := verify.GenesisTrustRoot{ChainID: 3, Height: 1, HeaderHash: h.HeaderHash}
			raw, err := json.Marshal(anchor)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "PRIVATE_GENESIS.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			a, aCalls := genesisPeer(t, h, false)
			b, bCalls := genesisPeer(t, h, false)
			var out, diagnostics bytes.Buffer
			err = runWithOutput([]string{"--peers", a + "," + b, "--genesis-config", path}, &out, &diagnostics)
			if err == nil || err.Error() != "observation does not match the explicit genesis shape" ||
				out.Len() != 0 || aCalls.Load() != 1 || bCalls.Load() != 1 ||
				strings.Contains(diagnostics.String(), "PRIVATE") {
				t.Fatal("internally consistent custom observation bypassed the genesis shape boundary")
			}
		})
	}
}
