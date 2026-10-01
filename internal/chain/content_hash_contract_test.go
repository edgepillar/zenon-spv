package chain

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"math"
	"slices"
	"sort"
	"sync"
	"testing"
)

// A deliberately simple byte-level oracle: do not call AccountHeader.Bytes,
// its encoder, or the production comparator. The node corpus separately pins
// expected roots; this oracle exercises arbitrary order, ties and full widths.
func referenceContentBytes(headers []AccountHeader) []byte {
	rows := make([][]byte, len(headers))
	for i, h := range headers {
		row := append([]byte(nil), h.Address[:]...)
		row = binary.BigEndian.AppendUint64(row, h.Height)
		rows[i] = append(row, h.Hash[:]...)
	}
	sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i], rows[j]) < 0 })
	return bytes.Join(rows, nil)
}

func contentBoundaryHeaders() []AccountHeader {
	return []AccountHeader{
		{Address: Address{19: 1}, Height: math.MaxUint64, Hash: Hash{31: 1}},
		{Address: Address{19: 1}, Height: 256, Hash: Hash{31: 1}},
		{Address: Address{19: 1}, Height: 255, Hash: Hash{31: 255}},
		{Address: Address{19: 1}, Height: 1 << 32, Hash: Hash{31: 1}},
		{Address: Address{19: 1}, Height: 1<<32 - 1, Hash: Hash{31: 1}},
		{Address: Address{19: 1}, Height: 1<<53 + 1, Hash: Hash{31: 1}},
		{Address: Address{19: 1}, Height: 256, Hash: Hash{31: 0}},
		{Address: Address{19: 1}, Height: 256, Hash: Hash{0: 1}},
		{Address: Address{0: 1}, Height: 0, Hash: Hash{31: 0}},
		{Address: Address{19: 1}, Height: 0, Hash: Hash{31: 0}},
		{Address: Address{19: 1}, Height: 256, Hash: Hash{31: 1}}, // Duplicate must remain.
	}
}

func checkContentSerialization(t testing.TB, headers []AccountHeader) {
	t.Helper()
	before := slices.Clone(headers)
	want := Hash(sha3.Sum256(referenceContentBytes(headers)))
	if got := MomentumContentHash(headers); got != want {
		t.Fatal("content hash differs from canonical byte concatenation")
	}
	if !slices.Equal(headers, before) {
		t.Fatal("content hashing modified the caller's headers")
	}
	for _, h := range headers {
		if !bytes.Equal(h.Bytes(), referenceContentBytes([]AccountHeader{h})) {
			t.Fatal("account-header encoding differs from the byte oracle")
		}
	}
}

func TestMomentumContentHashSerializationContract(t *testing.T) {
	boundary := contentBoundaryHeaders()
	reverse := slices.Clone(boundary)
	slices.Reverse(reverse)
	for _, tc := range []struct {
		name    string
		headers []AccountHeader
	}{
		{"nil", nil}, {"empty", []AccountHeader{}}, {"one", boundary[:1]},
		{"field boundaries and duplicate", boundary}, {"reversed boundaries", reverse},
		{"all equal", slices.Repeat(boundary[:1], 257)},
	} {
		t.Run(tc.name, func(t *testing.T) { checkContentSerialization(t, tc.headers) })
	}
	t.Run("duplicates are committed", func(t *testing.T) {
		if MomentumContentHash(boundary[:1]) == MomentumContentHash(slices.Repeat(boundary[:1], 2)) {
			t.Fatal("duplicate content was deduplicated")
		}
	})
	t.Run("shared immutable input", func(t *testing.T) {
		before := slices.Clone(boundary)
		want := Hash(sha3.Sum256(referenceContentBytes(boundary)))
		var readers sync.WaitGroup
		for range 8 {
			readers.Go(func() {
				for range 32 {
					if MomentumContentHash(boundary) != want {
						t.Error("concurrent content read changed the root")
					}
				}
			})
		}
		readers.Wait()
		if !slices.Equal(boundary, before) {
			t.Fatal("concurrent reads modified input")
		}
	})
}

func FuzzMomentumContentHashSerialization(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, AccountHeaderRawLen))
	f.Add(bytes.Repeat([]byte{255}, AccountHeaderRawLen*2))
	f.Add(referenceContentBytes(contentBoundaryHeaders()))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 256*AccountHeaderRawLen {
			return
		}
		headers := make([]AccountHeader, len(raw)/AccountHeaderRawLen)
		for i := range headers {
			row := raw[i*AccountHeaderRawLen : (i+1)*AccountHeaderRawLen]
			copy(headers[i].Address[:], row[:AddressSize])
			headers[i].Height = binary.BigEndian.Uint64(row[AddressSize : AddressSize+8])
			copy(headers[i].Hash[:], row[AddressSize+8:])
		}
		checkContentSerialization(t, headers)
		want := MomentumContentHash(headers)
		slices.Reverse(headers)
		if MomentumContentHash(headers) != want {
			t.Fatal("reversing a content list changed its root")
		}
	})
}
