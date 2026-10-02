package conformance_test

import (
	"encoding/json"
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
