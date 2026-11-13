// SPDX-License-Identifier: MIT

package fetch

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestCandidateRPCHashJSONCompatibility(t *testing.T) {
	text := strings.Repeat("01", 32)
	quoted := `"` + text + `"`
	var want chain.Hash
	for i := range want {
		want[i] = 1
	}
	escaped := escapedCandidateHash(text)
	if len(escaped) != 2+6*64 {
		t.Fatal("incorrect escaped boundary fixture")
	}
	for _, tc := range []struct {
		name  string
		raw   string
		valid bool
	}{
		{"literal", quoted, true},
		{"fully_escaped_at_bound", string(escaped), true},
		{"mixed_escaped", `"\u0030` + text[1:] + `"`, true},
		{"JSON_whitespace", " \t\r\n" + quoted + " \n", true},
		{"Unicode_whitespace", "\u00a0" + quoted, false},
		{"short", `"` + text[1:] + `"`, false},
		{"long", `"` + text + `0"`, false},
		{"prefix", `"0x` + text + `"`, false},
		{"uppercase", `"` + strings.Repeat("AF", 32) + `"`, false},
		{"escaped_uppercase", string(escapedCandidateHash(strings.Repeat("AF", 32))), false},
		{"invalid_first", `"g` + text[1:] + `"`, false},
		{"invalid_middle", `"` + text[:31] + "g" + text[32:] + `"`, false},
		{"invalid_last", `"` + text[:63] + `g"`, false},
		{"null", `null`, false},
		{"boolean", `true`, false},
		{"number", `123`, false},
		{"array", `[]`, false},
		{"object", `{}`, false},
		{"empty_string", `""`, false},
		{"empty_input", ``, false},
		{"trailing_value", quoted + ` ""`, false},
		{"bad_escape", `"\x00` + text[2:] + `"`, false},
		{"embedded_NUL", `"\u0000` + text[1:] + `"`, false},
		{"unterminated", quoted[:len(quoted)-1], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeCandidateRPCHash([]byte(tc.raw))
			if tc.valid {
				if err != nil || got != want {
					t.Fatal("valid hash spelling changed")
				}
			} else if err != ErrCandidateV3Momentum || got != (chain.Hash{}) {
				t.Fatal("invalid scalar must return no hash and the fixed error")
			}
			before := chain.Hash{0x77}
			target := before
			raw := append(append([]byte(`{"hash":`), tc.raw...), '}')
			err = decodeCandidateRPCObject(raw, map[string]any{"hash": &target})
			if !json.Valid([]byte(tc.raw)) {
				// A malformed complete object can fail after a valid prefix was
				// decoded. Only the public candidate API promises to discard the
				// whole local result; this internal field loop is not transactional.
				if err != ErrCandidateV3Momentum {
					t.Fatal("malformed object did not return the fixed error")
				}
				return
			}
			if tc.valid {
				if err != nil || target != want {
					t.Fatal("object hash policy changed")
				}
			} else if err != ErrCandidateV3Momentum || target != before {
				t.Fatal("invalid hash must not publish a partially decoded prefix")
			}
		})
	}
}

func TestCandidateRPCHashOversizedTokenAllocations(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"literal", []byte(`"` + strings.Repeat("0", 128*1024) + `"`)},
		{"escaped", escapedCandidateHash(strings.Repeat("0", 32768))},
		{"non_string", []byte(strings.Repeat("0", 128*1024))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeCandidateRPCHash(tc.raw)
			if err != ErrCandidateV3Momentum || got != (chain.Hash{}) {
				t.Fatal("oversized token did not refuse")
			}
			allocs := testing.AllocsPerRun(5, func() {
				candidateRPCHashSink, candidateRPCHashError = decodeCandidateRPCHash(tc.raw)
			})
			if allocs != 0 {
				t.Fatalf("oversized hash scalar allocated: %v", allocs)
			}
		})
	}
}

func TestCandidateV3HashSpellingsPreserveRecordedHeader(t *testing.T) {
	row := candidateRPCRows(t)[0]
	want, err := DecodeCandidateV3Momentum([]byte(row.Wire))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hash", "previousHash", "changesHash", "stateRoot"} {
		t.Run(name, func(t *testing.T) {
			fields := candidateRPCFields(t, row.Wire)
			var text string
			if json.Unmarshal(fields[name], &text) != nil {
				t.Fatal("recorded hash field is not text")
			}
			fields[name] = escapedCandidateHash(text)
			got, err := DecodeCandidateV3Momentum(candidateRPCJSON(t, fields))
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("escaped field changed the recorded header projection")
			}
			candidateRPCRefused(t, append(candidateRPCJSON(t, fields), []byte(` {}`)...))
			fields[name] = json.RawMessage(`"` + strings.Repeat("0", 16*1024) + `"`)
			candidateRPCRefused(t, candidateRPCJSON(t, fields))
		})
	}
}

func TestCandidateStateWitnessHashSpellings(t *testing.T) {
	root := strings.Repeat("01", 32)
	for _, tc := range []struct {
		name  string
		value []byte
		valid bool
	}{
		{"literal", []byte(`"` + root + `"`), true},
		{"escaped", escapedCandidateHash(root), true},
		{"oversized", []byte(`"` + strings.Repeat("0", 16*1024) + `"`), false},
		{"prefix", []byte(`"0x` + root + `"`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := candidateRPCJSON(t, map[string]any{
				"root": json.RawMessage(tc.value), "value": nil,
				"proof": base64.StdEncoding.EncodeToString(make([]byte, 99)),
			})
			if int64(len(raw)) > MaxCandidateStateResponseBytes {
				t.Fatal("hash refusal fixture exceeds the outer transport limit")
			}
			got, err := DecodeCandidateStateWitness(raw)
			if tc.valid {
				if err != nil || !bytes.Equal(got.Root[:], bytes.Repeat([]byte{1}, 32)) || len(got.Proof) != 99 || got.Value != nil {
					t.Fatal("candidate witness projection changed")
				}
			} else if err != ErrCandidateStateWitness || got.Proof != nil || got.Value != nil || got.Root != (chain.Hash{}) {
				t.Fatal("invalid root returned a partial candidate witness")
			}
		})
	}
}
