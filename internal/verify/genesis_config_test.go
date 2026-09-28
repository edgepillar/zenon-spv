package verify

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/0x3639/zenon-spv/internal/chain"
)

const syntheticAnchorHash = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
const validAnchorConfig = `{"chain_id":7,"height":12,"header_hash":"` + syntheticAnchorHash + `"}`

func TestGenesisConfigStrictFields(t *testing.T) {
	cases := map[string]string{
		"empty input": "", "null object": `null`, "empty object": `{}`, "array": `[]`,
		"truncated":         validAnchorConfig[:len(validAnchorConfig)-1],
		"missing chain":     strings.Replace(validAnchorConfig, `"chain_id":7,`, "", 1),
		"missing height":    strings.Replace(validAnchorConfig, `"height":12,`, "", 1),
		"missing hash":      `{"chain_id":7,"height":12}`,
		"null chain":        strings.Replace(validAnchorConfig, `"chain_id":7`, `"chain_id":null`, 1),
		"null height":       strings.Replace(validAnchorConfig, `"height":12`, `"height":null`, 1),
		"null hash":         strings.Replace(validAnchorConfig, `"`+syntheticAnchorHash+`"`, `null`, 1),
		"zero height":       strings.Replace(validAnchorConfig, `"height":12`, `"height":0`, 1),
		"zero hash":         strings.Replace(validAnchorConfig, syntheticAnchorHash, strings.Repeat("0", 64), 1),
		"short hash":        strings.Replace(validAnchorConfig, syntheticAnchorHash, "01", 1),
		"invalid hash":      strings.Replace(validAnchorConfig, syntheticAnchorHash, strings.Repeat("g", 64), 1),
		"array hash":        strings.Replace(validAnchorConfig, `"`+syntheticAnchorHash+`"`, `[1]`, 1),
		"unknown field":     `{"private_unknown_key":true,` + validAnchorConfig[1:],
		"case alias":        strings.Replace(validAnchorConfig, "chain_id", "CHAIN_ID", 1),
		"duplicate chain":   `{"chain_id":8,` + validAnchorConfig[1:],
		"duplicate height":  `{"height":13,` + validAnchorConfig[1:],
		"duplicate hash":    `{"header_hash":"` + syntheticAnchorHash + `",` + validAnchorConfig[1:],
		"escaped duplicate": `{"chain\u005fid":7,` + validAnchorConfig[1:],
		"trailing object":   validAnchorConfig + `{}`,
		"trailing null":     validAnchorConfig + `null`,
		"trailing garbage":  validAnchorConfig + `x`,
		"trailing comma":    validAnchorConfig[:len(validAnchorConfig)-1] + `,}`,
	}
	for _, field := range []string{`"chain_id":7`, `"height":12`} {
		name, _, _ := strings.Cut(field, ":")
		for _, value := range []string{"-1", "1.5", "1e2", "18446744073709551616", `"7"`, "true", "{}"} {
			cases[name+"="+value] = strings.Replace(validAnchorConfig, field, name+":"+value, 1)
		}
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "anchor.json")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := LoadGenesisFromConfig(path)
			if got != (GenesisTrustRoot{}) || !errors.Is(err, ErrInvalidGenesis) {
				t.Fatalf("invalid configuration returned anchor=%+v err=%v", got, err)
			}
			if strings.Contains(err.Error(), "private_unknown_key") {
				t.Fatal("untrusted field name reached the error message")
			}
		})
	}
}

func TestGenesisConfigValidBoundaries(t *testing.T) {
	for _, id := range []uint64{0, MainnetChainID, math.MaxUint64} {
		want := GenesisTrustRoot{ChainID: id, Height: math.MaxUint64, HeaderHash: chain.Hash{1}}
		raw, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		for _, input := range []string{string(raw), " \n" + string(raw) + "\t", strings.Replace(string(raw), `"header_hash":"`, `"header_hash":"0x`, 1)} {
			got, err := readGenesisConfig(strings.NewReader(input))
			if err != nil || got != want {
				t.Fatalf("explicit chain ID %d / terminal height: got=%+v err=%v", id, got, err)
			}
		}
		if _, err := NewVerifiedState(want, VerifyOptions{Policy: DefaultPolicy()}); err != nil {
			t.Fatalf("valid explicit anchor rejected by owned state: %v", err)
		}
	}
}

func TestGenesisConfigByteLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anchor.json")
	raw := validAnchorConfig + strings.Repeat(" ", MaxGenesisConfigBytes-len(validAnchorConfig))
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGenesisFromConfig(path); err != nil {
		t.Fatalf("valid file exactly at the cap: %v", err)
	}
	if err := os.WriteFile(path, []byte(raw+" "), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadGenesisFromConfig(path); got != (GenesisTrustRoot{}) || !errors.Is(err, ErrGenesisConfigTooLarge) {
		t.Fatalf("oversized file returned anchor=%+v err=%v", got, err)
	}
	input := strings.NewReader(raw + strings.Repeat(" ", MaxGenesisConfigBytes))
	before := input.Len()
	if got, err := readGenesisConfig(input); got != (GenesisTrustRoot{}) || !errors.Is(err, ErrGenesisConfigTooLarge) {
		t.Fatalf("oversized stream returned anchor=%+v err=%v", got, err)
	}
	if read := before - input.Len(); read != MaxGenesisConfigBytes+1 {
		t.Fatalf("read %d bytes, want at most cap plus one", read)
	}
	readErr := errors.New("synthetic read failure")
	if got, err := readGenesisConfig(iotest.ErrReader(readErr)); got != (GenesisTrustRoot{}) || !errors.Is(err, readErr) {
		t.Fatalf("read failure returned anchor=%+v err=%v", got, err)
	}
}

func FuzzGenesisConfig(f *testing.F) {
	for _, seed := range []string{validAnchorConfig, `null`, `{}`, `{"height":1,"height":2}`, validAnchorConfig + `{}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got, err := readGenesisConfig(strings.NewReader(input))
		if err != nil {
			if got != (GenesisTrustRoot{}) {
				t.Fatal("failed configuration returned a partial anchor")
			}
			return
		}
		if len(input) > MaxGenesisConfigBytes || got.Height == 0 || got.HeaderHash.IsZero() {
			t.Fatal("accepted configuration violates structural bounds")
		}
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if again, err := readGenesisConfig(strings.NewReader(string(raw))); err != nil || again != got {
			t.Fatalf("accepted anchor did not round-trip: %v", err)
		}
	})
}
