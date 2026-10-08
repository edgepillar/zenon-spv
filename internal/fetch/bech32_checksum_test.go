package fetch

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

type bech32AddressVector struct {
	Encoded     string   `json:"encoded"`
	DecodedHex  string   `json:"decoded_hex"`
	Occurrences int      `json:"occurrences"`
	Expected    [20]byte `json:"-"`
}

func loadBech32AddressVectors(t testing.TB) []bech32AddressVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/bech32-address-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Version int                   `json:"format_version"`
		Total   int                   `json:"total_occurrences"`
		Vectors []bech32AddressVector `json:"vectors"`
	}
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.Version != 1 || document.Total != 191 || len(document.Vectors) != 49 {
		t.Fatal("address fixture shape changed")
	}
	total := 0
	for i := range document.Vectors {
		v := &document.Vectors[i]
		decoded, err := hex.DecodeString(v.DecodedHex)
		if err != nil || len(decoded) != 20 || v.Occurrences <= 0 {
			t.Fatal("invalid independent address vector")
		}
		copy(v.Expected[:], decoded)
		total += v.Occurrences
	}
	if total != document.Total {
		t.Fatal("address fixture occurrence count changed")
	}
	return document.Vectors
}

func TestBech32NodeAddressVectors(t *testing.T) {
	for i, vector := range loadBech32AddressVectors(t) {
		t.Run(fmt.Sprintf("vector-%02d", i), func(t *testing.T) {
			for _, encoded := range []string{vector.Encoded, strings.ToUpper(vector.Encoded)} {
				got, err := DecodeZenonAddress(encoded)
				if err != nil || got != vector.Expected {
					t.Fatalf("address bytes changed: %v", err)
				}
			}
			altered := vector.Encoded[:len(vector.Encoded)-1] + "q"
			if altered == vector.Encoded {
				altered = altered[:len(altered)-1] + "p"
			}
			got, err := DecodeZenonAddress(altered)
			reference, previous := addressConcatReference(altered)
			if err == nil || got != ([20]byte{}) || got != reference || reflect.TypeOf(err) != reflect.TypeOf(previous) || err.Error() != previous.Error() {
				t.Fatal("checksum corruption or error contract changed")
			}
		})
	}
}

func TestBech32ChecksumPartitionVectors(t *testing.T) {
	// Literal checksum values from independent Python arithmetic on byte(i)%32.
	for _, vector := range []struct {
		size     int
		checksum uint32
	}{
		{0, 0x00000001},
		{1, 0x00000020},
		{3, 0x00008022},
		{7, 0x1df679c0},
		{38, 0x3f9b5c58},
		{4096, 0x18852f13},
	} {
		values := make([]byte, vector.size)
		for i := range values {
			values[i] = byte(i % 32)
		}
		for _, cut := range []int{0, len(values) / 2, len(values)} {
			got := bech32Polymod(values[:cut], nil, values[cut:])
			if got != vector.checksum {
				t.Fatalf("partition checksum changed at size %d cut %d", vector.size, cut)
			}
		}
	}
	if bech32Polymod() != 1 {
		t.Fatal("empty checksum changed")
	}
}

func FuzzBech32DecoderChecksumParts(f *testing.F) {
	for _, encoded := range []string{"", "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f", "z1qxemdeddedxaccelerat0rxxxxxxxxxxp4tk22", "zts1znnxxxxxxxxxxxxx9z4ulx", "z1Qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f", "z1\x80"} {
		f.Add(encoded)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		if len(encoded) > 4096 {
			t.Skip()
		}
		for _, hrp := range []string{"z", "zts"} {
			got, err := bech32Decode(encoded, hrp)
			previous, oldErr := decodeChecksumConcatReference(encoded, hrp)
			if !bytes.Equal(got, previous) || reflect.TypeOf(err) != reflect.TypeOf(oldErr) {
				t.Fatal("decoder bytes or error type changed")
			}
			if err != nil && err.Error() != oldErr.Error() {
				t.Fatal("decoder error changed")
			}
		}
	})
}
