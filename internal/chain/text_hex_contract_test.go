package chain

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Exact codec bodies from ed5bc3ec7030c33bfa91a2eb58abb379744c0cf6, with
// signatures adapted for a test-only reference. They preserve legacy errors,
// prefix handling and receiver behavior independently of the new buffers.
func hashTextReferenceMarshal(h Hash) ([]byte, error) {
	return []byte(hex.EncodeToString(h[:])), nil
}

func hashTextReferenceUnmarshal(h *Hash, text []byte) error {
	s := strings.TrimPrefix(string(text), "0x")
	if len(s) != 2*HashSize {
		return errors.New("chain.Hash: invalid hex length")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	copy(h[:], b)
	return nil
}

func addressTextReferenceMarshal(a Address) ([]byte, error) {
	return []byte(hex.EncodeToString(a[:])), nil
}

func addressTextReferenceUnmarshal(a *Address, text []byte) error {
	s := strings.TrimPrefix(string(text), "0x")
	if len(s) != 2*AddressSize {
		return errors.New("chain.Address: invalid hex length")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	copy(a[:], b)
	return nil
}

type chainTextValue interface {
	~[AddressSize]byte | ~[HashSize]byte
}

// Do not call the production encoder or encoding/hex for expected bytes.
func chainTextOracle[T chainTextValue](value T) []byte {
	const digits = "0123456789abcdef"
	text := make([]byte, 2*len(value))
	for i := 0; i < len(value); i++ {
		text[2*i], text[2*i+1] = digits[value[i]>>4], digits[value[i]&15]
	}
	return text
}

func checkChainTextDecode[T chainTextValue](t testing.TB, seed T, text []byte,
	decode, reference func(*T, []byte) error) {
	t.Helper()
	before := bytes.Clone(text)
	got, want := seed, seed
	err, oldErr := decode(&got, text), reference(&want, text)
	if !reflect.DeepEqual(err, oldErr) || got != want || !bytes.Equal(text, before) {
		t.Fatal("hex conversion differs from the pinned reference or changed its input")
	}
	if err != nil && got != seed {
		t.Fatal("failed hex conversion changed its receiver")
	}
}

func chainTextControls[T chainTextValue](t *testing.T, seed T,
	marshal, referenceMarshal func(T) ([]byte, error), decode, referenceDecode func(*T, []byte) error) (int, int, int) {
	t.Helper()
	values, encoded, lengths := 0, 0, 0
	for position := 0; position < len(seed); position++ {
		for octet := range 256 {
			value := seed
			value[position] = byte(octet)
			want := chainTextOracle(value)
			got, err := marshal(value)
			old, oldErr := referenceMarshal(value)
			if err != nil || oldErr != nil || !bytes.Equal(got, want) || !bytes.Equal(old, want) {
				t.Fatal("hex encoder differs from independent nibble bytes")
			}
			got[0] ^= 1
			again, err := marshal(value)
			if err != nil || !bytes.Equal(again, want) {
				t.Fatal("hex encoder returned a shared mutable buffer")
			}
			var roundTrip T
			if err := decode(&roundTrip, want); err != nil || roundTrip != value {
				t.Fatal("independent hex bytes did not decode to their exact value")
			}
			values++
		}
	}
	valid := chainTextOracle(seed)
	// Every possible byte at every encoded position, with and without the
	// optional lowercase prefix. This includes invalid late digits after a
	// decoded prefix, uppercase hex, NULs, non-ASCII and malformed UTF-8.
	for _, prefix := range []string{"", "0x"} {
		for position := range valid {
			for octet := range 256 {
				text := append([]byte(prefix), valid...)
				text[len(prefix)+position] = byte(octet)
				checkChainTextDecode(t, seed, text, decode, referenceDecode)
				encoded++
			}
		}
		for length := 0; length <= len(valid)+6; length++ {
			text := append([]byte(prefix), bytes.Repeat([]byte{'a'}, length)...)
			checkChainTextDecode(t, seed, text, decode, referenceDecode)
			lengths++
		}
	}
	for _, text := range [][]byte{nil, {}, []byte("0x"), []byte("0X"),
		append([]byte("0X"), valid...), append([]byte("0x0x"), valid...),
		append([]byte(" "), valid...), append(bytes.Clone(valid), ' ')} {
		checkChainTextDecode(t, seed, text, decode, referenceDecode)
	}
	// encoding/json's TextMarshaler/TextUnmarshaler path must retain its wire
	// bytes, prefix/case compatibility, null behavior and error atomicity.
	raw, err := json.Marshal(seed)
	if err != nil || string(raw) != `"`+string(valid)+`"` {
		t.Fatal("JSON changed the canonical lowercase hex representation")
	}
	for _, text := range [][]byte{valid, bytes.ToUpper(valid), append([]byte("0x"), valid...),
		append([]byte("0x"), bytes.ToUpper(valid)...)} {
		var got T
		if err := json.Unmarshal(append(append([]byte{'"'}, text...), '"'), &got); err != nil || got != seed {
			t.Fatal("JSON lost an accepted hex spelling")
		}
	}
	got := seed
	if err := json.Unmarshal([]byte("null"), &got); err != nil || got != seed {
		t.Fatal("JSON null changed a fixed-size receiver")
	}
	invalid := bytes.Clone(valid)
	invalid[len(invalid)-1] = 'g'
	if err := json.Unmarshal(append(append([]byte{'"'}, invalid...), '"'), &got); err == nil || got != seed {
		t.Fatal("invalid JSON hex changed the receiver or was accepted")
	}
	return values, encoded, lengths
}

func TestChainTextHexContract(t *testing.T) {
	var hash Hash
	var address Address
	for i := range hash {
		hash[i] = byte(7*i + 13)
	}
	for i := range address {
		address[i] = byte(11*i + 17)
	}
	values, encoded, lengths := 0, 0, 0
	t.Run("Hash", func(t *testing.T) {
		v, e, l := chainTextControls(t, hash, Hash.MarshalText, hashTextReferenceMarshal,
			(*Hash).UnmarshalText, hashTextReferenceUnmarshal)
		values, encoded, lengths = values+v, encoded+e, lengths+l
	})
	t.Run("Address", func(t *testing.T) {
		v, e, l := chainTextControls(t, address, Address.MarshalText, addressTextReferenceMarshal,
			(*Address).UnmarshalText, addressTextReferenceUnmarshal)
		values, encoded, lengths = values+v, encoded+e, lengths+l
	})
	if values != 13312 || encoded != 53248 || lengths != 236 {
		t.Fatal("finite hex coverage changed")
	}
	t.Logf("chain-text-hex-controls {\"schema_version\":1,\"types\":2,\"value_position_cases\":%d,\"encoded_byte_cases\":%d,\"length_cases\":%d,\"failure_atomicity\":true,\"input_preservation\":true,\"json_checked\":true}",
		values, encoded, lengths)
}

func FuzzChainTextHexContract(f *testing.F) {
	for _, text := range [][]byte{nil, []byte("0x"), bytes.Repeat([]byte{'a'}, 40),
		bytes.Repeat([]byte{'F'}, 64), append([]byte("0x"), bytes.Repeat([]byte{'b'}, 64)...),
		append(bytes.Repeat([]byte{'0'}, 63), 255)} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		if len(text) > 256 {
			return
		}
		checkChainTextDecode(t, Hash{1, 2, 3}, text, (*Hash).UnmarshalText, hashTextReferenceUnmarshal)
		checkChainTextDecode(t, Address{4, 5, 6}, text, (*Address).UnmarshalText, addressTextReferenceUnmarshal)
	})
}

var chainTextBenchmarkBytes []byte

func benchmarkChainTextHex[T chainTextValue](b *testing.B, value T,
	marshal, referenceMarshal func(T) ([]byte, error), decode, referenceDecode func(*T, []byte) error) {
	text := chainTextOracle(value)
	for _, mode := range []struct {
		name    string
		marshal func(T) ([]byte, error)
		decode  func(*T, []byte) error
	}{
		{"reference", referenceMarshal, referenceDecode}, {"buffers", marshal, decode},
	} {
		b.Run(fmt.Sprintf("Marshal/%s", mode.name), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var err error
				chainTextBenchmarkBytes, err = mode.marshal(value)
				if err != nil {
					b.Fatal(err)
				}
			}
			if !bytes.Equal(chainTextBenchmarkBytes, text) {
				b.Fatal("measured encoder changed its bytes")
			}
		})
		b.Run(fmt.Sprintf("Unmarshal/%s", mode.name), func(b *testing.B) {
			var got T
			b.ReportAllocs()
			for b.Loop() {
				if err := mode.decode(&got, text); err != nil {
					b.Fatal(err)
				}
			}
			if got != value {
				b.Fatal("measured decoder changed its value")
			}
		})
	}
}

func BenchmarkChainTextHex(b *testing.B) {
	b.Run("Hash", func(b *testing.B) {
		benchmarkChainTextHex(b, Hash{1, 2, 3}, Hash.MarshalText, hashTextReferenceMarshal,
			(*Hash).UnmarshalText, hashTextReferenceUnmarshal)
	})
	b.Run("Address", func(b *testing.B) {
		benchmarkChainTextHex(b, Address{4, 5, 6}, Address.MarshalText, addressTextReferenceMarshal,
			(*Address).UnmarshalText, addressTextReferenceUnmarshal)
	})
}
