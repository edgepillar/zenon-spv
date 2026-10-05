package fetch

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Capture the parent checksum concatenation and decoder bodies as a reference.
// Expected address bytes come from the independent Python fixture, not this code.
func checksumConcatReference(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (b>>i)&1 != 0 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func decodeChecksumConcatReference(bech, wantHRP string) ([]byte, error) {
	if strings.ToLower(bech) != bech && strings.ToUpper(bech) != bech {
		return nil, errors.New("bech32: mixed case")
	}
	bech = strings.ToLower(bech)
	pos := strings.LastIndex(bech, "1")
	if pos < 1 || pos+7 > len(bech) {
		return nil, errors.New("bech32: bad separator position")
	}
	hrp := bech[:pos]
	if hrp != wantHRP {
		return nil, fmt.Errorf("bech32: HRP %q != %q", hrp, wantHRP)
	}
	data := make([]byte, len(bech)-pos-1)
	for i := 0; i < len(data); i++ {
		c := bech[pos+1+i]
		if c >= 128 || bech32CharsetIdx[c] < 0 {
			return nil, fmt.Errorf("bech32: invalid char %q at %d", c, pos+1+i)
		}
		data[i] = byte(bech32CharsetIdx[c])
	}
	if checksumConcatReference(append(bech32HrpExpand(hrp), data...)) != 1 {
		return nil, errors.New("bech32: checksum mismatch")
	}
	return data[:len(data)-6], nil
}

func addressConcatReference(z string) ([20]byte, error) {
	data5, err := decodeChecksumConcatReference(z, "z")
	if err != nil {
		return [20]byte{}, err
	}
	raw, err := convertBits5to8(data5)
	if err != nil {
		return [20]byte{}, err
	}
	if len(raw) != 20 {
		return [20]byte{}, fmt.Errorf("address: length %d != 20", len(raw))
	}
	var out [20]byte
	copy(out[:], raw)
	return out, nil
}

func BenchmarkRPCAddressChecksum(b *testing.B) {
	vectors := loadBech32AddressVectors(b)
	for _, size := range []int{1, 49, 191} {
		cases := make([]bech32AddressVector, 0, size)
		if size == 191 {
			for _, v := range vectors {
				for n := 0; n < v.Occurrences; n++ {
					cases = append(cases, v)
				}
			}
		} else {
			cases = append(cases, vectors[:size]...)
		}
		if len(cases) != size {
			b.Fatal("address occurrence count changed")
		}
		for _, mode := range []struct {
			name   string
			decode func(string) ([20]byte, error)
		}{{"copy_reference", addressConcatReference}, {"checksum_parts", DecodeZenonAddress}} {
			b.Run(fmt.Sprintf("%d/%s", size, mode.name), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size * 40))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for _, v := range cases {
						got, err := mode.decode(v.Encoded)
						if err != nil || got != v.Expected {
							b.Fatalf("address bytes changed: %v", err)
						}
					}
				}
			})
		}
	}
}
