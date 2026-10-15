package verify

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Keep the positional assertion on a locally defined type: a new Header field
// must break compilation rather than silently escape the model's comparison.
type sequenceHeaderShape chain.Header

var _ = sequenceHeaderShape{0, 0, chain.Hash{}, chain.Hash{}, 0, 0,
	chain.Hash{}, chain.Hash{}, chain.Hash{}, nil, nil, 0, 0}

// Compare every header field without reflection in the full-window oracle.
// bytes.Equal alone would erase reflect.DeepEqual's nil/empty distinction.
// This helper neither validates headers nor supplies expected verifier results.
func sequenceHeadersEqual(a, b chain.Header) bool {
	return a.Version == b.Version && a.ChainIdentifier == b.ChainIdentifier &&
		a.HeaderHash == b.HeaderHash && a.PreviousHash == b.PreviousHash &&
		a.Height == b.Height && a.TimestampUnix == b.TimestampUnix &&
		a.DataHash == b.DataHash && a.ContentHash == b.ContentHash && a.ChangesHash == b.ChangesHash &&
		(a.PublicKey == nil) == (b.PublicKey == nil) && bytes.Equal(a.PublicKey, b.PublicKey) &&
		(a.Signature == nil) == (b.Signature == nil) && bytes.Equal(a.Signature, b.Signature) &&
		a.NextFusionPrice == b.NextFusionPrice && a.NextWorkPrice == b.NextWorkPrice
}

func sequenceComparisonHeader() chain.Header {
	h := chain.Header{Version: 2, ChainIdentifier: math.MaxUint64, Height: 1 << 63,
		TimestampUnix: 0x123456789abcdef0, NextFusionPrice: math.MaxUint64 - 1, NextWorkPrice: 1}
	for i := range chain.HashSize {
		h.HeaderHash[i], h.PreviousHash[i] = byte(i), byte(i+32)
		h.DataHash[i], h.ContentHash[i], h.ChangesHash[i] = byte(i+64), byte(i+96), byte(i+128)
	}
	h.PublicKey, h.Signature = make([]byte, 32), make([]byte, 64)
	for i := range h.PublicKey {
		h.PublicKey[i] = byte(i*7 + 3)
	}
	for i := range h.Signature {
		h.Signature[i] = byte(i*11 + 5)
	}
	return h
}

func TestSequenceHeaderEqualityMatchesReflection(t *testing.T) {
	base := sequenceComparisonHeader()
	bitMutations, shapePairs := 0, 0
	check := func(t *testing.T, a, b chain.Header) {
		t.Helper()
		want := reflect.DeepEqual(a, b)
		if sequenceHeadersEqual(a, b) != want || sequenceHeadersEqual(b, a) != want {
			t.Fatal("field comparison differs from the independent reflection oracle")
		}
	}
	// Change every bit of every scalar, hash, key and signature field. Do not
	// derive expected equality from hashing, serialization or verifier policy.
	for field := range reflect.TypeOf(base).NumField() {
		name := reflect.TypeOf(base).Field(field).Name
		t.Run(name, func(t *testing.T) {
			original := reflect.ValueOf(base).Field(field)
			width := 64
			if original.Kind() == reflect.Array || original.Kind() == reflect.Slice {
				width = original.Len() * 8
			}
			for bit := range width {
				changed := sequenceCopyHeader(base)
				value := reflect.ValueOf(&changed).Elem().Field(field)
				if value.Kind() == reflect.Uint64 {
					value.SetUint(value.Uint() ^ (uint64(1) << bit))
				} else {
					value = value.Index(bit / 8)
					value.SetUint(value.Uint() ^ (uint64(1) << (bit % 8)))
				}
				if reflect.DeepEqual(base, changed) {
					t.Fatal("mutation did not change the selected field")
				}
				check(t, base, changed)
				bitMutations++
			}
		})
	}
	// Include malformed lengths too: this is equality, not input validation.
	shapes := [][]byte{nil, {}, {0}, {1}, base.PublicKey, append(bytes.Clone(base.PublicKey), 0),
		base.Signature, append(bytes.Clone(base.Signature), 0)}
	var headers []chain.Header
	for _, key := range shapes {
		for _, signature := range shapes {
			h := base
			h.PublicKey, h.Signature = key, signature
			headers = append(headers, h)
		}
	}
	for _, a := range headers {
		for _, b := range headers {
			check(t, a, b)
			shapePairs++
		}
	}
	copy := sequenceCopyHeader(base)
	check(t, base, base)
	check(t, base, copy)
	// Different backing arrays and spare capacity must not change equality.
	copy.PublicKey = append(make([]byte, 0, 96), base.PublicKey...)
	copy.Signature = append(make([]byte, 0, 128), base.Signature...)
	check(t, base, copy)
	if !reflect.DeepEqual(base, sequenceComparisonHeader()) || bitMutations != 2432 || shapePairs != 4096 {
		t.Fatal("comparison mutated its inputs or lost finite coverage")
	}
	record, err := json.Marshal(struct {
		SchemaVersion int  `json:"schema_version"`
		Fields        int  `json:"header_fields"`
		Mutations     int  `json:"single_bit_mutations"`
		Pairs         int  `json:"slice_shape_pairs"`
		NilDistinct   bool `json:"nil_and_empty_remain_distinct"`
		Symmetric     bool `json:"both_argument_orders_checked"`
	}{1, 13, bitMutations, shapePairs, true, true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("retained-header-equality-controls %s", record)
}

var sequenceComparisonResult bool

func BenchmarkSequenceHeaderEquality(b *testing.B) {
	a := sequenceComparisonHeader()
	c := sequenceCopyHeader(a)
	for _, mode := range []struct {
		name  string
		equal func(chain.Header, chain.Header) bool
	}{
		{"reflection", func(a, b chain.Header) bool { return reflect.DeepEqual(a, b) }},
		{"fields", sequenceHeadersEqual},
	} {
		b.Run(mode.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				sequenceComparisonResult = mode.equal(a, c)
			}
			if !sequenceComparisonResult {
				b.Fatal("equal independently allocated headers differ")
			}
		})
	}
}
