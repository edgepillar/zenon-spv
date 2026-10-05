package proof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAccountAmountTokenPreservesLegacyDecoding(t *testing.T) {
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1)).String()
	wide := new(big.Int).Lsh(big.NewInt(1), 1024).String()
	for _, fields := range []string{
		``, `"amount":null`, `"amount":0`, `"amount":-0`, `"amount":-1`,
		`"amount":` + max, `"amount":` + wide,
		`"amount":1,"AMOUNT":2`, `"amount":1,"am\u006funt":null`,
		`"am\u006funt":2,"extension":{"amount":true}`,
		`"Amount":1,"AMOUNT":2,"height":3`,
	} {
		raw := []byte(`{"version":1,"segments":[{"blocks":[{` + fields + `},null],"blocks":[{` + fields + `}]}]}`)
		got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxAccountAmountBytes: DefaultMaxAccountAmountBytes})
		// The alias uses encoding/json's ordinary struct decoder independently
		// of the bounded bundle and account-amount wrappers.
		type plain HeaderBundle
		var expected plain
		if err != nil || json.Unmarshal(raw, &expected) != nil || !reflect.DeepEqual(got, HeaderBundle(expected)) {
			t.Fatalf("bounded scalar changed legacy fields %s: %v", fields, err)
		}
	}
	for _, token := range []string{`true`, `[]`, `{}`, `"123"`, `1.5`, `1e2`} {
		raw := []byte(`{"version":1,"segments":[{"blocks":[{"amount":` + token + `}]}]}`)
		type plain HeaderBundle
		var expected plain
		got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxAccountAmountBytes: DefaultMaxAccountAmountBytes})
		if err == nil || json.Unmarshal(raw, &expected) == nil || !reflect.DeepEqual(got, HeaderBundle{}) {
			t.Fatalf("invalid legacy scalar became decodable: %s", token)
		}
	}
}

func TestAccountAmountTokenBoundsEveryOccurrence(t *testing.T) {
	for _, alias := range []string{"amount", "AMOUNT", `am\u006funt`} {
		for _, size := range []int{32, 33, 1 << 20} {
			t.Run(fmt.Sprintf("%s/%d", alias, size), func(t *testing.T) {
				fields := fmt.Sprintf(`"%s":%s,"amount":null`, alias, strings.Repeat("9", size))
				raw := []byte(`{"version":1,"segments":[{"blocks":[{` + fields + `},"PRIVATE_UNREACHED_ROW"]}]}`)
				got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxAccountAmountBytes: 32})
				var bound *BundleByteLimitError
				if size == 32 {
					// The exact token cap permits ordinary parsing, which then
					// reaches the intentionally invalid following row.
					if err == nil || errors.As(err, &bound) {
						t.Fatalf("exact token cap refused an allowed scalar: %v", err)
					}
					valid := []byte(`{"version":1,"segments":[{"blocks":[{"amount":` + strings.Repeat("9", size) + `}]}]}`)
					decoded, err := unmarshalHeaderBundleJSON(valid, DecodeLimits{MaxAccountAmountBytes: 32})
					if err != nil || decoded.Segments[0].Blocks[0].Amount.String() != strings.Repeat("9", size) {
						t.Fatalf("exact token cap changed the amount: %v", err)
					}
					return
				}
				if !errors.As(err, &bound) || bound.Field != "segments.blocks.amount" || bound.Limit != 32 ||
					!reflect.DeepEqual(got, HeaderBundle{}) || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatalf("oversized replaced scalar was not refused before conversion and excess row: %v", err)
				}
				before := sampleBundle()
				unchanged := before
				if err := unchanged.unmarshalJSON(raw, DecodeLimits{MaxAccountAmountBytes: 32}); err == nil || !reflect.DeepEqual(unchanged, before) {
					t.Fatal("amount refusal partially changed the receiver")
				}
			})
		}
	}
}

func TestAccountAmountTokenLoaderPrecedenceAndOptOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	raw := []byte(`{"version":1,"segments":[{"blocks":[{"amount":` + strings.Repeat("9", DefaultMaxAccountAmountBytes+1) + `}]}]}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHeaderBundleWithLimits(path, int64(len(raw)-1), DecodeLimits{MaxAccountAmountBytes: 32}); !errors.Is(err, ErrBundleTooLarge) {
		t.Fatalf("file byte cap did not precede scalar decoding: %v", err)
	}
	for _, limits := range []DecodeLimits{{}, {MaxAccountAmountBytes: len(raw)}} {
		got, err := LoadHeaderBundleWithLimits(path, int64(len(raw)), limits)
		if err != nil || got.Segments[0].Blocks[0].Amount.BitLen() <= 255 {
			t.Fatalf("opt-out or generous token cap changed legacy conversion: %v", err)
		}
	}
	rowCap := []byte(`{"version":1,"segments":[{"blocks":[null,{"amount":12345}]}]}`)
	var count *BundleCountLimitError
	if _, err := unmarshalHeaderBundleJSON(rowCap, DecodeLimits{MaxSegmentBlocks: 1, MaxAccountAmountBytes: 4}); !errors.As(err, &count) {
		t.Fatalf("excess-row count cap did not precede its scalar: %v", err)
	}
	for _, token := range []string{"12345,", "01", "-", "12345 " + strings.Repeat("[", 10001)} {
		raw := []byte(`{"version":1,"segments":[{"blocks":[{"amount":` + token + `}]}]}`)
		var syntax *json.SyntaxError
		if got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxAccountAmountBytes: 4}); !errors.As(err, &syntax) || !reflect.DeepEqual(got, HeaderBundle{}) {
			t.Fatalf("amount guard bypassed whole-document JSON syntax checking: %v", err)
		}
	}
}

func FuzzAccountAmountTokenBound(f *testing.F) {
	for _, raw := range []string{"0", "-0", "1234", "12345", "null", "true", `"123"`, `[]`, `{"amount":1}`} {
		f.Add([]byte(raw), uint8(4))
	}
	f.Fuzz(func(t *testing.T, raw []byte, selected uint8) {
		if len(raw) > 4096 || !json.Valid(raw) {
			t.Skip()
		}
		limit := int(selected%32) + 1
		bundle := append([]byte(`{"version":1,"segments":[{"blocks":[{"am\u006funt":`), raw...)
		bundle = append(bundle, []byte(`,"amount":null}]}]}`)...)
		got, err := unmarshalHeaderBundleJSON(bundle, DecodeLimits{MaxAccountAmountBytes: limit})
		var bound *BundleByteLimitError
		if len(bytes.TrimSpace(raw)) > limit || len("null") > limit {
			// An under-cap invalid earlier token may fail legacy conversion
			// before reaching the later null; either failure must be atomic.
			if err == nil || !reflect.DeepEqual(got, HeaderBundle{}) {
				t.Fatal("oversized known token returned a partial or successful bundle")
			}
			if len(bytes.TrimSpace(raw)) > limit && (!errors.As(err, &bound) || bound.Field != "segments.blocks.amount" || bound.Limit != limit) {
				t.Fatalf("valid JSON oversized token bypassed early refusal: %v", err)
			}
			return
		}
		type plain HeaderBundle
		var expected plain
		legacyErr := json.Unmarshal(bundle, &expected)
		if (err == nil) != (legacyErr == nil) || (err == nil && !reflect.DeepEqual(got, HeaderBundle(expected))) || (err != nil && !reflect.DeepEqual(got, HeaderBundle{})) {
			t.Fatalf("under-cap token changed legacy decoding: %v / %v", err, legacyErr)
		}
	})
}
