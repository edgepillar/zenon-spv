package fetch

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// BenchmarkRPCOptionalBase64 compares only optional-key/signature decoding.
// The captured account bytes and synthetic line endings are prepared outside
// the timed region. It does not measure HTTP, signature verification or RSS.
func BenchmarkRPCOptionalBase64(b *testing.B) {
	account := loadOptionalBase64Account(b)
	for _, field := range []struct{ name, encoded string }{
		{"public_key", account.PublicKey}, {"signature", account.Signature},
	} {
		want, err := base64ToBytesOptionalReference(field.encoded)
		if err != nil {
			b.Fatal(err)
		}
		for _, lineBytes := range []int{0, 32 << 10, 1 << 20, 8 << 20} {
			encoded := strings.Repeat("\r\n", lineBytes/2) + field.encoded
			for _, mode := range []struct {
				name   string
				decode func(string) ([]byte, error)
			}{
				{"decode_string_reference", base64ToBytesOptionalReference},
				{"sized_optional", base64ToBytesOptional},
			} {
				b.Run(fmt.Sprintf("%s/%d/%s", field.name, lineBytes, mode.name), func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(len(encoded)))
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						got, err := mode.decode(encoded)
						if err != nil || !bytes.Equal(got, want) {
							b.Fatal("optional bytes changed")
						}
					}
				})
			}
		}
	}
}

// Exact body from b7b9857776ce9352017bb3ead19702aaca41cd73, renamed only.
// This reference is never used by production decoding.
func base64ToBytesOptionalReference(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}
