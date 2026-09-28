package chain

import (
	"bytes"
	"errors"
	"math/big"
	"testing"
)

func TestAccountAmountScalarBounds(t *testing.T) {
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))
	for _, amount := range []*big.Int{nil, new(big.Int), big.NewInt(1000), max} {
		if err := ValidateAccountAmount(amount); err != nil {
			t.Fatalf("valid scalar refused: %v", err)
		}
	}
	for _, amount := range []*big.Int{big.NewInt(-1), new(big.Int).Add(max, big.NewInt(1)), new(big.Int).Lsh(big.NewInt(1), 1024)} {
		if !errors.Is(ValidateAccountAmount(amount), ErrInvalidAccountAmount) {
			t.Fatal("invalid scalar accepted")
		}
	}
}

func TestAccountAmountBytesNeverTruncates(t *testing.T) {
	for _, bits := range []uint{255, 256, 512, 1024} {
		amount := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), bits), big.NewInt(1000))
		want := amount.Bytes()
		if len(want) < 32 {
			want = append(make([]byte, 32-len(want)), want...)
		}
		if got := accountAmountBytes(amount); !bytes.Equal(got, want) {
			t.Fatalf("lost high-order amount bytes at bit %d", bits)
		}
		b := AccountBlock{Amount: amount}
		hash := b.ComputeHash()
		b.Amount = big.NewInt(1000)
		if hash == b.ComputeHash() {
			t.Fatal("overflow amount aliases the low-value block hash")
		}
	}
}
