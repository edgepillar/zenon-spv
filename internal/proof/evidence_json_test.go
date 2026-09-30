package proof

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestNestedEvidenceDecodeCountLimits(t *testing.T) {
	for _, tc := range []struct {
		field, envelope string
		limits          DecodeLimits
	}{
		{"segments.blocks", `{"version":1,"segments":[{"blocks":%s}]}`, DecodeLimits{MaxSegmentBlocks: 2}},
		{"commitments.flat.sorted_headers", `{"version":1,"commitments":[{"flat":{"sorted_headers":%s}}]}`, DecodeLimits{MaxFlatEvidenceMembers: 2}},
		{"state_value_proofs.proof_nodes", `{"version":1,"state_value_proofs":[{"proof_nodes":%s}]}`, DecodeLimits{MaxStateProofNodes: 2}},
	} {
		t.Run(tc.field, func(t *testing.T) {
			for _, value := range []string{`null`, `[]`, `[null]`, `[null,null]`} {
				raw := []byte(fmt.Sprintf(tc.envelope, value))
				got, err := unmarshalHeaderBundleJSON(raw, tc.limits)
				type plain HeaderBundle
				var expected plain
				if err != nil || json.Unmarshal(raw, &expected) != nil || !reflect.DeepEqual(got, HeaderBundle(expected)) {
					t.Fatalf("valid nested evidence changed at or below its cap: %v", err)
				}
			}
			raw := []byte(fmt.Sprintf(tc.envelope, `[null,null,"PRIVATE_UNREACHED_ROW"]`))
			got, err := unmarshalHeaderBundleJSON(raw, tc.limits)
			var count *BundleCountLimitError
			if !errors.As(err, &count) || count.Field != tc.field || count.Limit != 2 || !reflect.DeepEqual(got, HeaderBundle{}) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("nested count limit decoded an excess row: %v", err)
			}
		})
	}
}

func TestNestedEvidenceDecodeAggregateBudgets(t *testing.T) {
	for _, tc := range []struct {
		name, field, raw string
		limits           DecodeLimits
	}{
		{"segments", "total_segment_blocks", `{"version":1,"segments":[{"blocks":[null,null]},{"blocks":[null,"PRIVATE_UNREACHED_ROW"]}]}`,
			DecodeLimits{MaxSegmentBlocks: 2, MaxTotalSegmentBlocks: 3}},
		{"flat commitments", "total_flat_evidence_members", `{"version":1,"commitments":[{"flat":{"sorted_headers":[null,null]}},{"flat":{"sorted_headers":[null,"PRIVATE_UNREACHED_ROW"]}}]}`,
			DecodeLimits{MaxFlatEvidenceMembers: 2, MaxTotalFlatEvidenceMembers: 3}},
		{"replaced blocks", "total_segment_blocks", `{"version":1,"segments":[{"blocks":[null,null],"BLOCKS":[null,"PRIVATE_UNREACHED_ROW"]}]}`,
			DecodeLimits{MaxSegmentBlocks: 2, MaxTotalSegmentBlocks: 3}},
		{"cleared flat", "total_flat_evidence_members", `{"version":1,"commitments":[{"flat":{"sorted_headers":[null,null]},"flat":null},{"flat":{"sorted_headers":[null,"PRIVATE_UNREACHED_ROW"]}}]}`,
			DecodeLimits{MaxFlatEvidenceMembers: 2, MaxTotalFlatEvidenceMembers: 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var count *BundleCountLimitError
			got := sampleBundle()
			before := sampleBundle()
			err := got.unmarshalJSON([]byte(tc.raw), tc.limits)
			if !errors.As(err, &count) || count.Field != tc.field || count.Limit != 3 || !reflect.DeepEqual(got, before) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("aggregate decode budget was bypassed: %v", err)
			}
			// Failed and successful parses cannot consume a reusable policy's
			// budget. New loads start with fresh counters.
			valid := strings.Replace(tc.raw, `,"PRIVATE_UNREACHED_ROW"`, "", 1)
			for range 2 {
				if _, err := unmarshalHeaderBundleJSON([]byte(valid), tc.limits); err != nil {
					t.Fatalf("exact aggregate count lost slots to an earlier load: %v", err)
				}
			}
		})
	}
}

func TestNestedEvidenceDecodePreservesFieldSemantics(t *testing.T) {
	limits := DecodeLimits{MaxFlatEvidenceMembers: 2, MaxSegmentBlocks: 2, MaxStateProofNodes: 2}
	for _, raw := range []string{
		`{"version":1,"segments":[null,{}, {"BLOCKS":[null],"blocks":null}]}`,
		`{"version":1,"segments":[{"blocks":[null,null]},{"blocks":[null,null]}]}`,
		`{"version":1,"commitments":[null,{}, {"flat":null}, {"flat":{}}]}`,
		`{"version":1,"commitments":[{"flat":{"sorted_headers":[{}]},"flat":{}}]}`,
		`{"version":1,"commitments":[{"flat":{"SORTED_HEADER\u017f":[null]},"flat":null,"flat":{}}]}`,
		`{"version":1,"commitments":[{"flat":{"unknown":[true],"sorted_headers":[null],"sorted_headers":null}}]}`,
		`{"version":1,"state_value_proofs":[{"PROOF_NODE\u017f":["AA==",null]},{"proof_nodes":[null,null]}]}`,
		`{"version":1,"state_value_proofs":[{"proof_nodes":[null],"proof_nodes":null}]}`,
	} {
		got, err := unmarshalHeaderBundleJSON([]byte(raw), limits)
		type plain HeaderBundle
		var expected plain
		if err != nil || json.Unmarshal([]byte(raw), &expected) != nil || !reflect.DeepEqual(got, HeaderBundle(expected)) {
			t.Fatalf("nested field interpretation changed: %v", err)
		}
	}
	for _, raw := range []string{
		`{"version":1,"segments":[{"blocks":"PRIVATE","blocks":[]}]}`,
		`{"version":1,"commitments":[{"flat":1,"flat":{}}]}`,
		`{"version":1,"commitments":[{"flat":{"sorted_headers":true,"sorted_headers":[]}}]}`,
		`{"version":1,"state_value_proofs":[{"proof_nodes":{},"proof_nodes":[]}]}`,
	} {
		got, err := unmarshalHeaderBundleJSON([]byte(raw), limits)
		if err == nil || !reflect.DeepEqual(got, HeaderBundle{}) {
			t.Fatal("a later nested value hid an earlier type error")
		}
	}
}
