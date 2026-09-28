package fetch

import (
	"errors"
	"math/big"
	"regexp"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestRPCAccountAmountBoundsBeforeHashing(t *testing.T) {
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))
	for _, text := range []string{"", "0", "0000", "+0", "1000", "+1000", strings.Repeat("0", 4096) + "1000", max.String()} {
		got, err := parseDecimalBigInt(text)
		if err != nil || chain.ValidateAccountAmount(got) != nil {
			t.Fatalf("valid decimal refused: %v", err)
		}
	}
	for _, text := range []string{"-1", "-0", "+", "0+1", "00-1", "++1", " 1", "1_0", "1e2", new(big.Int).Add(max, big.NewInt(1)).String(), strings.Repeat("9", 4096), "private-invalid-value"} {
		got, err := parseDecimalBigInt(text)
		if !errors.Is(err, chain.ErrInvalidAccountAmount) || got != nil {
			t.Fatal("invalid decimal was not rejected")
		}
		if strings.Contains(err.Error(), text) && len(text) > 10 {
			t.Fatal("amount diagnostic echoed untrusted input")
		}
	}
	block := queryAccountBlock(t, 1, "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f")
	if _, err := convertAndVerifyAccountBlock(block); err != nil {
		t.Fatalf("baseline fixture: %v", err)
	}
	amount, ok := new(big.Int).SetString(block.Amount, 10)
	if !ok {
		t.Fatal("invalid fixture amount")
	}
	block.Amount = new(big.Int).Add(amount, new(big.Int).Lsh(big.NewInt(1), 256)).String()
	if _, err := convertAndVerifyAccountBlock(block); !errors.Is(err, chain.ErrInvalidAccountAmount) {
		t.Fatalf("overflow alias reached hash acceptance: %v", err)
	}
}

func FuzzRPCAccountAmountScalar(f *testing.F) {
	for _, seed := range []string{"", "0", "+1000", "0005", "-0", "0+5", "private-invalid-value", "57896044618658097711785492504343953926634992332820282019728792003956564819967"} {
		f.Add(seed)
	}
	syntax := regexp.MustCompile(`^\+?[0-9]+$`)
	ceiling := new(big.Int).Lsh(big.NewInt(1), 255)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip()
		}
		want := new(big.Int)
		valid := input == ""
		if syntax.MatchString(input) {
			_, valid = want.SetString(input, 10)
			valid = valid && want.Cmp(ceiling) < 0
		}
		got, err := parseDecimalBigInt(input)
		if valid {
			if err != nil || got == nil || got.Cmp(want) != 0 {
				t.Fatal("valid decimal changed value or was refused")
			}
		} else if !errors.Is(err, chain.ErrInvalidAccountAmount) || got != nil {
			t.Fatal("invalid decimal returned an amount")
		}
	})
}
