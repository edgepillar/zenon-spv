package fetch

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Isolate data-preimage decode and hashing, excluding JSON/RPC conversion and
// input construction. Both modes produce the same expected SHA3-256 hash.
func BenchmarkRPCDataHashDecode(b *testing.B) {
	for _, size := range []int{32 << 10, 1 << 20, 8 << 20} {
		raw := make([]byte, size)
		for i := range raw {
			raw[i] = byte(i)
		}
		encoded, expected := base64.StdEncoding.EncodeToString(raw), sha3sum(raw)
		for _, mode := range []struct {
			name string
			hash func(string) (chain.Hash, error)
		}{
			{"buffer_reference", bufferedRPCDataHash}, {"stream_hash", hashRPCData},
		} {
			b.Run(fmt.Sprintf("%d/%s", size, mode.name), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					got, err := mode.hash(encoded)
					if err != nil || got != expected {
						b.Fatalf("data preimage hash changed: %v", err)
					}
				}
			})
		}
	}
}
