package conformance_test

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// BenchmarkEnvelopeHash isolates one signed-envelope hash. Decoding is outside
// B.Loop; each iteration must match a digest from the pinned node corpus.
func BenchmarkEnvelopeHash(b *testing.B) {
	c := loadCorpus(b)
	for _, tc := range []struct {
		name    string
		index   int
		version uint64
		bytes   int
	}{{"HeaderV1", 4, 1, 160}, {"HeaderV2", 8, 2, 176}} {
		b.Run(tc.name, func(b *testing.B) {
			h := c.Vectors[tc.index].Header
			if h.Version != tc.version {
				b.Fatal("benchmark header fixture changed")
			}
			b.ReportAllocs()
			for b.Loop() {
				if h.ComputeHash() != h.HeaderHash {
					b.Fatal("envelope hash differs from the pinned node digest")
				}
			}
			b.ReportMetric(float64(tc.bytes), "preimage-bytes/op")
		})
	}
	raw, err := os.ReadFile("../testdata/conformance/account-amounts.json")
	if err != nil {
		b.Fatal(err)
	}
	var amounts struct {
		FormatVersion int                     `json:"format_version"`
		Source        struct{ Commit string } `json:"source"`
		Vectors       []struct {
			Name  string             `json:"name"`
			Block chain.AccountBlock `json:"block"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &amounts); err != nil {
		b.Fatal(err)
	}
	if amounts.FormatVersion != 1 || amounts.Source.Commit != "3a4131e63881058b6ce2ee81d3a41d0033fafc99" || len(amounts.Vectors) != 7 {
		b.Fatal("unexpected account amount corpus")
	}
	for _, tc := range []struct {
		name  string
		index int
		label string
	}{{"AccountZero", 0, "zero"}, {"AccountMax255", 2, "max-255-bits"}} {
		b.Run(tc.name, func(b *testing.B) {
			v := amounts.Vectors[tc.index]
			if v.Name != tc.label || chain.ValidateAccountAmount(v.Block.Amount) != nil {
				b.Fatal("benchmark amount fixture changed")
			}
			b.ReportAllocs()
			for b.Loop() {
				if v.Block.ComputeHash() != v.Block.BlockHash {
					b.Fatal("envelope hash differs from the pinned node digest")
				}
			}
			b.ReportMetric(306, "preimage-bytes/op")
		})
	}
}

// BenchmarkAccountAmountHash retains all seven node amount vectors and a nil
// form of the recorded zero. Invalid magnitudes remain serialization controls;
// a matching hash does not make them acceptable RPC or segment inputs.
func BenchmarkAccountAmountHash(b *testing.B) {
	raw, err := os.ReadFile("../testdata/conformance/account-amounts.json")
	if err != nil {
		b.Fatal(err)
	}
	var corpus struct {
		FormatVersion int                     `json:"format_version"`
		Source        struct{ Commit string } `json:"source"`
		Vectors       []struct {
			Name        string             `json:"name"`
			ScalarValid bool               `json:"scalar_valid"`
			Block       chain.AccountBlock `json:"block"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		b.Fatal(err)
	}
	if corpus.FormatVersion != 1 || corpus.Source.Commit != "3a4131e63881058b6ce2ee81d3a41d0033fafc99" || len(corpus.Vectors) != 7 || corpus.Vectors[0].Name != "zero" {
		b.Fatal("unexpected account amount corpus")
	}
	nilZero := corpus.Vectors[0]
	nilZero.Name, nilZero.Block.Amount = "nil-zero", nil
	corpus.Vectors = append(corpus.Vectors, nilZero)
	for _, vector := range corpus.Vectors {
		b.Run(vector.Name, func(b *testing.B) {
			block := vector.Block
			if (chain.ValidateAccountAmount(block.Amount) == nil) != vector.ScalarValid {
				b.Fatal("node scalar classification changed")
			}
			original := block.Amount
			var value *big.Int
			width := 32
			if original != nil {
				value = new(big.Int).Set(original)
				width = max(width, (original.BitLen()+7)/8)
			}
			b.ReportAllocs()
			for b.Loop() {
				if block.ComputeHash() != block.BlockHash {
					b.Fatal("amount hash differs from the pinned node digest")
				}
			}
			if block.Amount != original || (original != nil && original.Cmp(value) != 0) {
				b.Fatal("amount hashing modified caller-owned input")
			}
			b.ReportMetric(float64(306+width-32), "preimage-bytes/op")
		})
	}
}
