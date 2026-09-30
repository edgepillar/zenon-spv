package proof

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBundleDecodeCountLimits(t *testing.T) {
	for _, field := range []string{"headers", "commitments", "segments", "state_value_proofs"} {
		for _, alias := range []string{field, strings.ToUpper(field), strings.ReplaceAll(field, "s", `\u017f`)} {
			t.Run(alias, func(t *testing.T) {
				limits := DecodeLimits{MaxHeaders: 2, MaxCommitments: 2, MaxSegments: 2, MaxStateValueProofs: 2}
				for _, value := range []string{`null`, `[]`, `[{}]`, `[{},null]`} {
					raw := []byte(fmt.Sprintf(`{"version":1,"%s":%s}`, alias, value))
					got, err := unmarshalHeaderBundleJSON(raw, limits)
					type plain HeaderBundle
					var expected plain
					if err != nil || json.Unmarshal(raw, &expected) != nil || !reflect.DeepEqual(got, HeaderBundle(expected)) {
						t.Fatalf("valid window changed at or below the count cap: %v", err)
					}
				}
				raw := []byte(fmt.Sprintf(`{"version":1,"%s":[{},null,"PRIVATE_UNREACHED_ROW"]}`, alias))
				got, err := unmarshalHeaderBundleJSON(raw, limits)
				var bound *BundleCountLimitError
				if !errors.As(err, &bound) || bound.Field != field || bound.Limit != 2 || !reflect.DeepEqual(got, HeaderBundle{}) || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatalf("count guard did not precede excess-row decoding: %v", err)
				}
				before := sampleBundle()
				unchanged := before
				if err := unchanged.unmarshalJSON(raw, limits); err == nil || !reflect.DeepEqual(unchanged, before) {
					t.Fatal("count failure partially changed the receiver")
				}
			})
		}
	}
}

func TestBundleDecodeLimitsPreserveDuplicateGuard(t *testing.T) {
	for _, field := range []string{"headers", "commitments", "segments", "state_value_proofs"} {
		raw := []byte(fmt.Sprintf(`{"version":1,"%s":[{}],"%s":null}`, field, strings.ToUpper(field)))
		if _, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxHeaders: 1, MaxCommitments: 1, MaxSegments: 1, MaxStateValueProofs: 1}); err == nil || !strings.Contains(err.Error(), "duplicate bundle field") {
			t.Fatalf("bounded decoding lost the duplicate-field guard: %v", err)
		}
	}
}

func TestLoadBundleByteAndCountLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	raw := []byte(`{"version":1,"headers":[{},{}]}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, maxBytes := range []int64{0, int64(len(raw)), math.MaxInt64} {
		if got, err := LoadHeaderBundleWithLimits(path, maxBytes, DecodeLimits{MaxHeaders: 2}); err != nil || len(got.Headers) != 2 {
			t.Fatalf("exact count at byte cap %d: %v", maxBytes, err)
		}
	}
	if _, err := LoadHeaderBundleWithLimits(path, int64(len(raw)-1), DecodeLimits{MaxHeaders: 1}); !errors.Is(err, ErrBundleTooLarge) {
		t.Fatalf("byte limit did not fire before JSON decoding: %v", err)
	}
	var count *BundleCountLimitError
	if _, err := LoadHeaderBundleWithLimits(path, int64(len(raw)), DecodeLimits{MaxHeaders: 1}); !errors.As(err, &count) {
		t.Fatalf("file loader lost its count refusal: %v", err)
	}
	for _, limits := range []DecodeLimits{
		{MaxHeaders: -1}, {MaxCommitments: -1}, {MaxSegments: -1}, {MaxStateValueProofs: -1},
		{MaxFlatEvidenceMembers: -1}, {MaxTotalFlatEvidenceMembers: -1}, {MaxSegmentBlocks: -1}, {MaxTotalSegmentBlocks: -1}, {MaxStateProofNodes: -1}, {MaxStateProofBytes: -1},
	} {
		if _, err := LoadHeaderBundleWithLimits(path+"-absent", 1024, limits); err == nil || errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalid limits reached the filesystem: %v", err)
		}
	}
	if got, err := LoadHeaderBundleBounded(path, int64(len(raw))); err != nil || len(got.Headers) != 2 {
		t.Fatalf("legacy byte-only loader changed: %v", err)
	}
}

func TestBundleDecodeRejectsMalformedArrays(t *testing.T) {
	for _, value := range []string{`{}`, `1`, `"PRIVATE"`, `true`, `[`, `[,{}]`, `[{},]`, `["bad"]`} {
		raw := []byte(fmt.Sprintf(`{"version":1,"headers":%s}`, value))
		got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxHeaders: 2})
		if err == nil || !reflect.DeepEqual(got, HeaderBundle{}) {
			t.Fatalf("malformed array produced a bundle: %v", err)
		}
	}
}

func TestBundleDecodePreservesStandardJSONDepthLimit(t *testing.T) {
	// The outer bundle object counts toward encoding/json's nesting limit.
	// Streaming fields must not reset that limit for an unknown nested value.
	raw := []byte(`{"version":1,"extension":` + strings.Repeat("[", 10000) + "0" + strings.Repeat("]", 10000) + "}")
	var syntax *json.SyntaxError
	if got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxHeaders: 1}); !errors.As(err, &syntax) || !reflect.DeepEqual(got, HeaderBundle{}) {
		t.Fatalf("bundle loader bypassed the standard JSON depth limit: %v", err)
	}
}

func FuzzBundleDecodeLimits(f *testing.F) {
	for _, raw := range []string{
		emptyBundleJSON, `null`, `{"version":1,"headers":[null,{}]}`,
		`{"version":1,"commitments":[{"flat":{"sorted_headers":[{}]}}]}`,
		`{"version":1,"segments":[{"blocks":[]}]}`, `{"version":1,"state_value_proofs":[{}]}`,
		`{"HEADERS":[{}],"headers":[]}`, `{"headers":[{},]}`, `{} {}`,
		`{"segments":[{"blocks":[null],"blocks":[]}]}`,
		`{"commitments":[{"flat":{"sorted_headers":[null]},"flat":{}}]}`,
		`{"state_value_proofs":[{"proof_nodes":["AA==",null]}]}`,
	} {
		f.Add([]byte(raw), uint8(1))
	}
	f.Fuzz(func(t *testing.T, raw []byte, count uint8) {
		if len(raw) > 4096 {
			t.Skip()
		}
		limit := int(count % 8)
		limits := DecodeLimits{MaxHeaders: limit, MaxCommitments: limit, MaxSegments: limit, MaxStateValueProofs: limit,
			MaxFlatEvidenceMembers: limit, MaxTotalFlatEvidenceMembers: limit, MaxSegmentBlocks: limit, MaxTotalSegmentBlocks: limit, MaxStateProofNodes: limit, MaxStateProofBytes: limit}
		before := sampleBundle()
		got := before
		if err := got.unmarshalJSON(raw, limits); err != nil {
			if !reflect.DeepEqual(got, before) {
				t.Fatal("failed decode mutated the receiver")
			}
			return
		}
		type plain HeaderBundle
		var expected plain
		if err := json.Unmarshal(raw, &expected); err != nil || !reflect.DeepEqual(got, HeaderBundle(expected)) {
			t.Fatalf("bounded decoding changed the field interpretation: %v", err)
		}
		if limit > 0 && (len(got.Headers) > limit || len(got.Commitments) > limit || len(got.Segments) > limit || len(got.StateValueProofs) > limit) {
			t.Fatal("successful decoding exceeded an array count cap")
		}
		if limit > 0 {
			flat, blocks := 0, 0
			for _, evidence := range got.Commitments {
				if evidence.Flat != nil {
					flat += len(evidence.Flat.SortedHeaders)
				}
			}
			for _, segment := range got.Segments {
				blocks += len(segment.Blocks)
			}
			if flat > limit || blocks > limit {
				t.Fatal("successful decoding exceeded an aggregate count cap")
			}
			for _, proof := range got.StateValueProofs {
				if len(proof.ProofNodes) > limit {
					t.Fatal("successful decoding exceeded a proof-node count cap")
				}
				remaining := limit
				for _, node := range proof.ProofNodes {
					if len(node) > remaining {
						t.Fatal("successful decoding exceeded a proof-node byte cap")
					}
					remaining -= len(node)
				}
			}
		}
	})
}
