package proof

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestStateProofDecodeByteLimits(t *testing.T) {
	for name, nodes := range map[string]string{
		"single base64 node": `["AAECAw=="]`,
		"base64 aggregate":   `["AAEC","Aw=="]`,
		"single byte array":  `[[0,1,2,3]]`,
		"mixed aggregate":    `["AAEC",["PRIVATE_UNREACHED_BYTE"]]`,
		"escaped padding":    `["AAECAw\u003d\u003d"]`,
		"ignored newlines":   `["A\r\nAECAw\r=\n=\r\n"]`,
	} {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`{"version":1,"state_value_proofs":[{"proof_nodes":` + nodes + `}]}`)
			got := sampleBundle()
			before := sampleBundle()
			err := got.unmarshalJSON(raw, DecodeLimits{MaxStateProofBytes: 3})
			var size *BundleByteLimitError
			if !errors.As(err, &size) || size.Field != "state_value_proofs.proof_nodes" || size.Limit != 3 || !reflect.DeepEqual(got, before) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("proof bytes exceeded the decoding budget: %v", err)
			}
		})
	}
}

func TestStateProofDecodeByteBudgetScope(t *testing.T) {
	for _, raw := range []string{
		`{"version":1,"state_value_proofs":[{"proof_nodes":["AAEC"],"proof_nodes":["Aw=="]}]}`,
		`{"version":1,"state_value_proofs":[{"proof_nodes":[[0,1,2]],"proof_nodes":null,"PROOF_NODE\u017f":[[3]]}]}`,
	} {
		limits := DecodeLimits{MaxStateProofBytes: 3}
		var size *BundleByteLimitError
		if got, err := unmarshalHeaderBundleJSON([]byte(raw), limits); !errors.As(err, &size) || !reflect.DeepEqual(got, HeaderBundle{}) {
			t.Fatalf("replaced proof nodes refunded decoded bytes: %v", err)
		}
		// Each proof and each new load starts with a fresh budget, even after
		// a prior load failed. Empty nodes consume zero decoded bytes.
		valid := []byte(`{"version":1,"state_value_proofs":[{"proof_nodes":["AAEC",null,"",[]]},{"proof_nodes":[[0,1,2]]}]}`)
		for range 2 {
			if _, err := unmarshalHeaderBundleJSON(valid, limits); err != nil {
				t.Fatalf("a different proof or load consumed this proof's budget: %v", err)
			}
		}
	}
}

func TestStateProofDecodeByteCompatibility(t *testing.T) {
	for _, nodes := range []string{
		`null`, `[]`, `[null]`, `[""]`, `[[]]`, `[[null,0,255]]`,
		`["AA=="]`, `["AAE="]`, `["AAEC"]`, `["AB=="]`,
		`["AA\r\nE=",[2]]`, `["\u0041A\u003d\u003d",null,[1,2]]`,
		`["\r\n\r\n",[0,1,2]]`,
	} {
		raw := []byte(`{"version":1,"state_value_proofs":[{"proof_nodes":` + nodes + `}]}`)
		type plain HeaderBundle
		var expected plain
		if err := json.Unmarshal(raw, &expected); err != nil {
			t.Fatal(err)
		}
		for _, limit := range []int{0, 3, math.MaxInt} {
			got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxStateProofBytes: limit})
			if err != nil || !reflect.DeepEqual(got, HeaderBundle(expected)) {
				t.Fatalf("valid proof bytes changed with limit %d: %v", limit, err)
			}
		}
	}
	for _, node := range []string{
		`1`, `true`, `{}`, `"*PRIVATE*"`, `"AAAAA"`, `"AA==AA=="`,
		`"AA==\r\nAA=="`, `"AA="`, `"A==="`, `"AAAA===="`, `"AA =="`,
		`[-1]`, `[256]`, `[1.0]`, `[1e0]`, `["PRIVATE"]`, `[[0]]`, `[{}]`,
	} {
		raw := []byte(`{"version":1,"state_value_proofs":[{"proof_nodes":[` + node + `],"proof_nodes":[]}]}`)
		if got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxStateProofBytes: 32}); err == nil || !reflect.DeepEqual(got, HeaderBundle{}) {
			t.Fatal("invalid byte encoding was accepted or hidden by a later field")
		}
	}
}

func FuzzProofNodeByteDecode(f *testing.F) {
	for _, raw := range []string{
		`null`, `[]`, `""`, `"AA=="`, `"AAE="`, `"AAEC"`, `"AAECAw=="`,
		`"AA\r\nE\u003d"`, `"AB=="`, `"AA==AA=="`, `"AA==\r\nAA=="`,
		`[null,0,255]`, `[-1]`, `[256]`, `[1.0]`, `[true]`, `{"secret":[]}`,
	} {
		f.Add([]byte(raw), uint8(3))
	}
	f.Fuzz(func(t *testing.T, raw []byte, capByte uint8) {
		if len(raw) > 4096 {
			t.Skip()
		}
		limit := int(capByte % 32)
		budget := &proofByteBudget{limit: limit, remaining: limit}
		before := []byte{99}
		got := append([]byte(nil), before...)
		err := json.Unmarshal(raw, &proofNodeJSON{target: &got, budget: budget})
		var expected []byte
		standardErr := json.Unmarshal(raw, &expected)
		if err != nil {
			if !reflect.DeepEqual(got, before) || budget.remaining != limit {
				t.Fatal("failed node decode mutated its receiver or budget")
			}
			if standardErr == nil && len(expected) <= limit {
				t.Fatalf("bounded decoder refused valid bytes within its budget: %v", err)
			}
			return
		}
		if standardErr != nil || !reflect.DeepEqual(got, expected) || len(got) > limit || budget.remaining != limit-len(expected) {
			t.Fatalf("bounded byte decode changed standard JSON semantics: %v", standardErr)
		}
	})
}
