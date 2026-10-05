package proof

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestBundleExtensionProjectionMatchesStandardJSON(t *testing.T) {
	for _, value := range []string{`null`, `true`, `0`, `1e999999`, `"metadata"`, `[]`,
		`{"headers":["PRIVATE_UNUSED_ROW"],"version":99}`, `{"same":1,"same":null}`,
		`{"metadata":"` + strings.Repeat("x", 1<<20) + `"}`, `[null,{"segments":true}]`,
	} {
		raw := []byte(`{"extension":` + value + `,"extension":null,` + emptyBundleJSON[1:])
		got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxHeaders: 1, MaxSegmentBlocks: 1, MaxAccountAmountBytes: DefaultMaxAccountAmountBytes})
		// This distinct type bypasses all custom bundle/evidence wrappers.
		type plain HeaderBundle
		var expected plain
		if err != nil || json.Unmarshal(raw, &expected) != nil || !reflect.DeepEqual(got, HeaderBundle(expected)) {
			t.Fatalf("extension discard changed standard field projection: %v", err)
		}
	}
}

func TestBundleExtensionDiscardPreservesFailureBoundaries(t *testing.T) {
	large := `{"extension":{"metadata":"` + strings.Repeat("x", 1<<20) + `"},`
	for _, fields := range []string{
		`"version":1,"headers":[],"heade\u0072s":null}`,
		`"version":1,"HEADERS":[],"header\u017f":null}`,
	} {
		got, before := sampleBundle(), sampleBundle()
		if err := json.Unmarshal([]byte(large+fields), &got); err == nil || !strings.Contains(err.Error(), "duplicate bundle field") || !reflect.DeepEqual(got, before) {
			t.Fatalf("discarding a large extension changed the duplicate guard or receiver: %v", err)
		}
	}
	raw := []byte(large + `"version":1,"headers":[null,"PRIVATE_UNREACHED_ROW"]}`)
	got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxHeaders: 1})
	var count *BundleCountLimitError
	if !errors.As(err, &count) || count.Field != "headers" || count.Limit != 1 || !reflect.DeepEqual(got, HeaderBundle{}) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("discarding an extension changed the count cap: %v", err)
	}
	for _, raw := range []string{
		`{"version":1,"extension":{"nested":[1,]}}`,
		`{"version":1,"extension":true} false`,
		`{"version":1,"extension":` + strings.Repeat("[", 10000) + "0" + strings.Repeat("]", 10000) + "}",
	} {
		got, before := sampleBundle(), sampleBundle()
		var syntax *json.SyntaxError
		if err := json.Unmarshal([]byte(raw), &got); !errors.As(err, &syntax) || !reflect.DeepEqual(got, before) {
			t.Fatalf("extension discard bypassed whole-document syntax/depth checks: %v", err)
		}
	}
}

func FuzzBundleExtensionProjection(f *testing.F) {
	for _, raw := range []string{`null`, `true`, `"metadata"`, `1e999999`, `{"headers":[]}`, `[1,{"version":99}]`} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) > 4096 || !json.Valid(value) {
			t.Skip()
		}
		raw := append([]byte(`{"extension":`), value...)
		raw = append(raw, []byte(`,"extension":null,`+emptyBundleJSON[1:])...)
		got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxHeaders: 1, MaxCommitments: 1, MaxSegments: 1, MaxStateValueProofs: 1, MaxAccountAmountBytes: DefaultMaxAccountAmountBytes})
		type plain HeaderBundle
		var expected plain
		if err != nil || json.Unmarshal(raw, &expected) != nil || !reflect.DeepEqual(got, HeaderBundle(expected)) {
			t.Fatalf("unused JSON value changed standard bundle projection: %v", err)
		}
	})
}
