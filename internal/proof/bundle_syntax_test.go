package proof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Retain the private adapter's exact callback from
// 6116c0c23b7d1d6a5d111a81753bc091036759be. The standalone decoder still
// validates its input, so this reference performs the previous two syntax
// passes. Field interpretation and nested budget decoders remain shared.
type bundleSyntaxReferenceDecoder struct {
	target *HeaderBundle
	limits DecodeLimits
}

func (decoder *bundleSyntaxReferenceDecoder) UnmarshalJSON(raw []byte) error {
	return decoder.target.unmarshalJSON(raw, decoder.limits)
}

func decodeBundleSyntaxReference(raw []byte, limits DecodeLimits) (HeaderBundle, error) {
	var got HeaderBundle
	if err := json.Unmarshal(raw, &bundleSyntaxReferenceDecoder{target: &got, limits: limits}); err != nil {
		return HeaderBundle{}, fmt.Errorf("parse bundle: %w", err)
	}
	if got.Version != WireVersion {
		return HeaderBundle{}, fmt.Errorf("unsupported wire version %d (expected %d)", got.Version, WireVersion)
	}
	return got, nil
}

func compareBundleSyntaxValidation(t testing.TB, raw []byte, limits DecodeLimits) {
	t.Helper()
	before := bytes.Clone(raw)
	got, err := unmarshalHeaderBundleJSON(raw, limits)
	want, referenceErr := decodeBundleSyntaxReference(raw, limits)
	if !reflect.DeepEqual(got, want) || (err == nil) != (referenceErr == nil) || err != nil && err.Error() != referenceErr.Error() {
		t.Fatalf("bundle projection or refusal differs: current=%v reference=%v", err, referenceErr)
	}
	var syntax, referenceSyntax *json.SyntaxError
	var typed, referenceTyped *json.UnmarshalTypeError
	var count, referenceCount *BundleCountLimitError
	var size, referenceSize *BundleByteLimitError
	if errors.As(err, &syntax) != errors.As(referenceErr, &referenceSyntax) || !reflect.DeepEqual(syntax, referenceSyntax) ||
		errors.As(err, &typed) != errors.As(referenceErr, &referenceTyped) || !reflect.DeepEqual(typed, referenceTyped) ||
		errors.As(err, &count) != errors.As(referenceErr, &referenceCount) || !reflect.DeepEqual(count, referenceCount) ||
		errors.As(err, &size) != errors.As(referenceErr, &referenceSize) || !reflect.DeepEqual(size, referenceSize) {
		t.Fatal("concrete syntax, type or resource error details changed")
	}
	current, reference, seed := sampleBundle(), sampleBundle(), sampleBundle()
	currentErr := json.Unmarshal(raw, &bundleJSONDecoder{target: &current, limits: limits})
	oldErr := json.Unmarshal(raw, &bundleSyntaxReferenceDecoder{target: &reference, limits: limits})
	if !reflect.DeepEqual(current, reference) || (currentErr == nil) != (oldErr == nil) || currentErr != nil && !reflect.DeepEqual(current, seed) {
		t.Fatal("adapter changed its projection or partially replaced a failed receiver")
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("bundle syntax reuse modified the input")
	}
}

func TestBundleSyntaxValidationReference(t *testing.T) {
	inputs := []string{
		emptyBundleJSON, " \n\t" + emptyBundleJSON + "\r\n", `{}`, `null`, `[]`, `1`, `true`, `"bundle"`, ``, ` `, `{`,
		`{"version":1,"headers":[{},null]}`,
		`{"version":1,"headers":[{},null,"UNREACHED"]}`,
		`{"ver\u0073ion":1,"HEADER\u017f":[],"extension":{"s":"\\\"{}[],:"}}`,
		`{"version":1,"extension":null,"extension":[false,1e-9,{"s":"\ud800"}]}`,
		`{"version":1,"headers":[],"headerſ":null}`,
		`{"version":1,"VERSION":1}`, `{"version":1,"version":null}`,
		`{"version":1,"chain_id":18446744073709551616}`,
		`{"version":1,"claimed_genesis":"invalid"}`, `{"version":1,"headers":false}`,
		`{"version":1,"commitments":[{"flat":{"sorted_headers":[null,null]},"flat":null},{"flat":{"sorted_headers":[null]}}]}`,
		`{"version":1,"segments":[{"blocks":[null,null],"BLOCKS":[null]}]}`,
		`{"version":1,"segments":[{"blocks":[{"amount":"12345"}]}]}`,
		`{"version":1,"state_value_proofs":[{"proof_nodes":["AAAA",null],"proof_nodes":["AA=="]}]}`,
		`{"version":2}`, `{"version":1} {}`, `{"version":1,"extension":[1,]}`,
		`{"version":1,"headers":[{},]}`, `{"version":1,"extension":"unterminated}`,
		"{\"\xff\":1,\"version\":1}",
	}
	for _, depth := range []int{9999, 10000} {
		inputs = append(inputs, `{"version":1,"extension":`+strings.Repeat("[", depth)+"0"+strings.Repeat("]", depth)+"}")
	}
	for i, raw := range inputs {
		for j, limits := range []DecodeLimits{
			{}, {MaxHeaders: 2, MaxCommitments: 2, MaxSegments: 2, MaxStateValueProofs: 2,
				MaxFlatEvidenceMembers: 2, MaxTotalFlatEvidenceMembers: 2, MaxSegmentBlocks: 2, MaxTotalSegmentBlocks: 2,
				MaxAccountAmountBytes: 4, MaxStateProofNodes: 2, MaxStateProofBytes: 2},
			{MaxHeaders: 1}, {MaxTotalFlatEvidenceMembers: -1},
		} {
			t.Run(fmt.Sprintf("case_%d/limits_%d", i, j), func(t *testing.T) {
				compareBundleSyntaxValidation(t, []byte(raw), limits)
			})
		}
	}
}

func TestBundleStandaloneSyntaxValidation(t *testing.T) {
	valid := []byte(`{"version":1,"headers":[],"extension":{"escaped":"\\\"","items":[true,null,1e-9]}}`)
	for end := range len(valid) {
		t.Run(fmt.Sprint(end), func(t *testing.T) {
			raw := valid[:end]
			for _, standard := range []bool{false, true} {
				got, before := sampleBundle(), sampleBundle()
				var err error
				if standard {
					err = json.Unmarshal(raw, &got)
				} else {
					err = got.UnmarshalJSON(raw)
				}
				var syntax *json.SyntaxError
				if !errors.As(err, &syntax) || !reflect.DeepEqual(got, before) {
					t.Fatal("standalone or standard JSON path skipped complete syntax validation or changed a failed receiver")
				}
			}
		})
	}
	var direct, standard HeaderBundle
	if err := direct.UnmarshalJSON(valid); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(valid, &standard); err != nil || !reflect.DeepEqual(direct, standard) {
		t.Fatal("valid standalone and standard projections differ")
	}
}

func TestBundleSyntaxValidationPrecedence(t *testing.T) {
	for _, raw := range []string{
		`{"version":1,"headers":[{},{}],"extension":[}`,     // Syntax precedes an early count refusal.
		`{"version":1,"version":1,"extension":"unfinished}`, // Syntax precedes duplicate detection.
		`{"version":1} true`,                                // A later value cannot be hidden by an earlier valid object.
	} {
		for _, limits := range []DecodeLimits{{MaxHeaders: 1}, {MaxHeaders: -1}} {
			var syntax *json.SyntaxError
			if got, err := unmarshalHeaderBundleJSON([]byte(raw), limits); !errors.As(err, &syntax) || !reflect.DeepEqual(got, HeaderBundle{}) {
				t.Fatal("loader no longer checks the complete document before limits or fields")
			}
		}
		// A direct bounded call retains its existing invalid-limits-first order.
		got, before := sampleBundle(), sampleBundle()
		err := got.unmarshalJSON([]byte(raw), DecodeLimits{MaxHeaders: -1})
		if err == nil || err.Error() != "bundle decode limits must be nonnegative" || !reflect.DeepEqual(got, before) {
			t.Fatal("direct bounded validation order or failed receiver changed")
		}
	}
}

func FuzzBundleSyntaxValidation(f *testing.F) {
	for _, raw := range []string{
		emptyBundleJSON, ``, `null`, `{"version":1,"headers":[],"headerſ":null}`,
		`{"version":1,"extension":{"s":"\\\"[]{}"}}`,
		`{"version":1,"commitments":[{"flat":{"sorted_headers":[{},null]}}]}`,
		`{"version":1,"state_value_proofs":[{"proof_nodes":["AA=="]}]}`,
	} {
		f.Add([]byte(raw), uint8(2))
	}
	f.Fuzz(func(t *testing.T, raw []byte, count uint8) {
		if len(raw) > 64<<10 {
			return
		}
		limit := int(count%8) - 1
		compareBundleSyntaxValidation(t, raw, DecodeLimits{
			MaxHeaders: limit, MaxCommitments: limit, MaxSegments: limit, MaxStateValueProofs: limit,
			MaxFlatEvidenceMembers: limit, MaxTotalFlatEvidenceMembers: limit, MaxSegmentBlocks: limit,
			MaxTotalSegmentBlocks: limit, MaxAccountAmountBytes: 64, MaxStateProofNodes: limit, MaxStateProofBytes: 256,
		})
	})
}

// Full repeated-wire arrays are used in both modes. Setup and full projection
// comparison are outside timing. These are decoder observations, not proof
// verification, peak RSS, network latency or representative workload claims.
func BenchmarkProofBundleSyntaxValidation(b *testing.B) {
	for _, grid := range []struct{ members, targets int }{{1000, 1}, {1000, 16}, {100000, 4}} {
		members := make([]chain.AccountHeader, grid.members)
		for i := range members {
			members[i] = chain.AccountHeader{Height: uint64(i + 1), Hash: chain.Hash{byte(i), byte(i >> 8)}}
		}
		bundle := HeaderBundle{Version: WireVersion, ChainID: 99, Commitments: make([]CommitmentEvidence, grid.targets)}
		for i := range bundle.Commitments {
			bundle.Commitments[i] = CommitmentEvidence{Height: 10001, Target: members[i*(grid.members-1)/max(1, grid.targets-1)], Flat: &FlatContentEvidence{SortedHeaders: members}}
		}
		raw, err := json.Marshal(bundle)
		if err != nil {
			b.Fatal(err)
		}
		limits := DecodeLimits{MaxCommitments: grid.targets, MaxFlatEvidenceMembers: grid.members, MaxTotalFlatEvidenceMembers: grid.members * grid.targets}
		for _, mode := range []struct {
			name   string
			decode func([]byte, DecodeLimits) (HeaderBundle, error)
		}{
			{"double_syntax_reference", decodeBundleSyntaxReference}, {"validated_callback", unmarshalHeaderBundleJSON},
		} {
			b.Run(fmt.Sprintf("M%d_P%d/%s", grid.members, grid.targets, mode.name), func(b *testing.B) {
				got, err := mode.decode(raw, limits)
				if err != nil || !reflect.DeepEqual(got, bundle) {
					b.Fatalf("benchmark projection differs: %v", err)
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				b.ResetTimer()
				for range b.N {
					got, err := mode.decode(raw, limits)
					if err != nil || len(got.Commitments) != grid.targets || len(got.Commitments[grid.targets-1].Flat.SortedHeaders) != grid.members || got.Commitments[grid.targets-1].Target != bundle.Commitments[grid.targets-1].Target {
						b.Fatal("benchmark decode failed")
					}
				}
			})
		}
	}
}
