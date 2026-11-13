// SPDX-License-Identifier: MIT

package fetch

import (
	"fmt"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

var candidateRPCHashSink chain.Hash
var candidateRPCHashError error

func escapedCandidateHash(text string) []byte {
	var b strings.Builder
	b.WriteByte('"')
	for i := range text {
		fmt.Fprintf(&b, "\\u%04x", text[i])
	}
	b.WriteByte('"')
	return []byte(b.String())
}

// This exercises the existing whole-object entry point in both the selected
// baseline overlay and current source. Input construction is outside timing;
// these are function observations, not process RSS or production budgets.
func BenchmarkCandidateRPCHashObject(b *testing.B) {
	text := strings.Repeat("0123456789abcdef", 4)
	for _, tc := range []struct {
		name  string
		value []byte
		valid bool
	}{
		{"literal", []byte(`"` + text + `"`), true},
		{"all_escaped", escapedCandidateHash(text), true},
		{"uppercase", []byte(`"` + strings.ToUpper(text) + `"`), false},
		{"oversized_literal", []byte(`"` + strings.Repeat("0", 128*1024) + `"`), false},
		{"oversized_escaped", escapedCandidateHash(strings.Repeat("0", 32768)), false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			raw := append(append([]byte(`{"hash":`), tc.value...), '}')
			var h chain.Hash
			fields := map[string]any{"hash": &h}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := decodeCandidateRPCObject(raw, fields)
				if (err == nil) != tc.valid {
					b.Fatal("unexpected hash decision")
				}
				candidateRPCHashSink, candidateRPCHashError = h, err
			}
		})
	}
}
