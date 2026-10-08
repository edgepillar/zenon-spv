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
	// SHA3-256 literals were independently derived with Python hashlib from
	// the byte(i) pattern, rather than the Go hash implementation under test.
	for _, vector := range []struct {
		size   int
		digest string
	}{
		{32 << 10, "3d69687d744b35b2c3a757240c5dc0f05a99f2402737cd776b8dfca8b6ecc667"},
		{1 << 20, "d968751128cfec8780ddfe859f11bdcd8b84e1f2175a1093fa9e776ad7fac6b1"},
		{8 << 20, "4e8bb6cbece65e0cb45aeaaf078bcfedfeb08912d1460e026872b47eb574f132"},
	} {
		size := vector.size
		raw := make([]byte, size)
		for i := range raw {
			raw[i] = byte(i)
		}
		encoded := base64.StdEncoding.EncodeToString(raw)
		expected, err := decodeHex32(vector.digest)
		if err != nil {
			b.Fatal(err)
		}
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
