package proof

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Synthetic invalid decimal input isolates bundle parsing and arbitrary-
// precision conversion. Input construction is outside the timed region.
// Decoding a scalar is not account-block verification or network evidence.
func BenchmarkProofAccountAmountDecode(b *testing.B) {
	for _, size := range []int{32 << 10, 256 << 10, 1 << 20} {
		raw := []byte(`{"version":1,"segments":[{"blocks":[{"amount":` + strings.Repeat("9", size) + `}]}]}`)
		b.Run(fmt.Sprintf("%d/legacy_conversion", size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxSegments: 1, MaxSegmentBlocks: 1, MaxTotalSegmentBlocks: 1})
				if err != nil || len(got.Segments) != 1 || len(got.Segments[0].Blocks) != 1 ||
					got.Segments[0].Blocks[0].Amount == nil || got.Segments[0].Blocks[0].Amount.BitLen() < size {
					b.Fatalf("legacy conversion did not decode the selected scalar: %v", err)
				}
			}
		})
		b.Run(fmt.Sprintf("%d/bounded_refusal", size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxSegments: 1, MaxSegmentBlocks: 1, MaxTotalSegmentBlocks: 1,
					MaxAccountAmountBytes: DefaultMaxAccountAmountBytes})
				var bound *BundleByteLimitError
				if !errors.As(err, &bound) || bound.Field != "segments.blocks.amount" || bound.Limit != DefaultMaxAccountAmountBytes || got.Version != 0 || got.Segments != nil {
					b.Fatalf("bounded conversion did not refuse the selected token atomically: %v", err)
				}
			}
		})
	}
}
