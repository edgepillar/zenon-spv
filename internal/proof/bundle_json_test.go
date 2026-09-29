package proof

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const emptyBundleJSON = `{"version":1,"chain_id":3,"claimed_genesis":"0000000000000000000000000000000000000000000000000000000000000000","headers":[],"commitments":[],"segments":[],"state_value_proofs":[]}`

func TestBundleJSONRejectsRepeatedControlFields(t *testing.T) {
	for _, field := range []struct{ name, value string }{
		{"version", "99"}, {"chain_id", "9"},
		{"claimed_genesis", `"0100000000000000000000000000000000000000000000000000000000000000"`},
		{"headers", `[{"version":99}]`}, {"commitments", "[{}]"}, {"segments", "[{}]"}, {"state_value_proofs", "[{}]"},
	} {
		for _, name := range []string{field.name, strings.ToUpper(field.name)} {
			t.Run(name, func(t *testing.T) {
				raw := []byte(`{"` + name + `":` + field.value + `,` + emptyBundleJSON[1:])
				if _, err := UnmarshalHeaderBundleJSON(raw); err == nil || !strings.Contains(err.Error(), "duplicate bundle field") {
					t.Fatalf("ambiguous bundle accepted: %v", err)
				}
				before := sampleBundle()
				got := before
				if err := json.Unmarshal(raw, &got); err == nil || !reflect.DeepEqual(got, before) {
					t.Fatal("direct JSON decode accepted duplicates or partially changed the receiver")
				}
			})
		}
	}
}

func TestBundleJSONKeepsAliasesAndExtensionFields(t *testing.T) {
	for _, name := range []string{`"headers"`, `"HEADERS"`, `"headerſ"`, `"heade\u0072s"`} {
		raw := strings.Replace(emptyBundleJSON, `"headers"`, name, 1)
		raw = `{"extension":{"headers":[{"version":99}]},"extension":null,` + raw[1:]
		got, err := UnmarshalHeaderBundleJSON([]byte(raw))
		if err != nil || got.Version != 1 || got.ChainID != 3 || got.Headers == nil {
			t.Fatalf("unambiguous compatibility input changed: %v", err)
		}
	}
	for _, raw := range []string{`null`, `[]`, `1`, `"bundle"`, `{`, `{"headers":false}`, emptyBundleJSON + ` true`} {
		got, before := sampleBundle(), sampleBundle()
		if err := got.UnmarshalJSON([]byte(raw)); err == nil || !reflect.DeepEqual(got, before) {
			t.Fatalf("invalid object accepted or changed the receiver: %s", raw)
		}
	}
	got := sampleBundle()
	if err := json.Unmarshal([]byte(`{"version":1,"chain_id":3}`), &got); err != nil || got.Headers != nil || got.ClaimedGenesis != (HeaderBundle{}).ClaimedGenesis {
		t.Fatal("successful decode carried evidence over from a previous object")
	}
}

func FuzzBundleJSONFieldAliases(f *testing.F) {
	f.Add(uint8(3), uint8(0), false, []byte("metadata"))
	f.Add(uint8(3), uint8(2), true, []byte{})
	f.Add(uint8(6), uint8(3), true, []byte{0, 255})
	f.Fuzz(func(t *testing.T, fieldIndex, variant uint8, duplicate bool, extension []byte) {
		extension = extension[:min(len(extension), 4096)]
		fields := []string{"version", "chain_id", "claimed_genesis", "headers", "commitments", "segments", "state_value_proofs"}
		field := fields[int(fieldIndex)%len(fields)]
		alias := field
		switch variant % 4 {
		case 1:
			alias = strings.ToUpper(field)
		case 2:
			alias = strings.ReplaceAll(field, "s", "ſ")
		}
		key, _ := json.Marshal(alias)
		if variant%4 == 3 {
			key = []byte(`"`)
			for _, r := range field {
				key = fmt.Appendf(key, `\u%04x`, r)
			}
			key = append(key, '"')
		}
		padding, _ := json.Marshal(extension)
		body := strings.Replace(emptyBundleJSON, `"`+field+`"`, string(key), 1)
		prefix := `{"extension":` + string(padding) + `,`
		if duplicate {
			prefix += `"` + field + `":null,`
		}
		raw := []byte(prefix + body[1:])
		got, before := sampleBundle(), sampleBundle()
		err := json.Unmarshal(raw, &got)
		if duplicate {
			if err == nil || !strings.Contains(err.Error(), "duplicate bundle field") || !reflect.DeepEqual(got, before) {
				t.Fatalf("duplicate alias accepted or partially applied: %v", err)
			}
			return
		}
		// A distinct type bypasses the new method and gives the standard
		// library's projection as an independent compatibility oracle.
		type plain HeaderBundle
		var want plain
		if err != nil || json.Unmarshal(raw, &want) != nil || !reflect.DeepEqual(got, HeaderBundle(want)) {
			t.Fatalf("unambiguous alias differs from standard decoding: %v", err)
		}
	})
}
