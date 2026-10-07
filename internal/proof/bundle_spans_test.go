package proof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Exact top-level decoder body from 1535fe57199295e13e64c007629abfa24b0d3328,
// with only its receiver signature adapted. Nested decoders stay shared so this
// reference isolates the replaced top-level buffering and binding behavior.
func unmarshalBundleBufferedReference(b *HeaderBundle, raw []byte, limits DecodeLimits) error {
	if err := limits.validate(); err != nil {
		return err
	}
	var decoded HeaderBundle
	evidence := newEvidenceDecoder(limits)
	fields := []struct {
		name   string
		target any
	}{
		{"version", &decoded.Version}, {"chain_id", &decoded.ChainID},
		{"claimed_genesis", &decoded.ClaimedGenesis},
		{"headers", &bundleRows[chain.Header]{target: &decoded.Headers, field: "headers", limit: limits.MaxHeaders}},
		{"commitments", &bundleRows[CommitmentEvidence]{target: &decoded.Commitments, field: "commitments", limit: limits.MaxCommitments, decode: evidence.commitment}},
		{"segments", &bundleRows[AccountSegment]{target: &decoded.Segments, field: "segments", limit: limits.MaxSegments, decode: evidence.segment}},
		{"state_value_proofs", &bundleRows[StateValueProof]{target: &decoded.StateValueProofs, field: "state_value_proofs", limit: limits.MaxStateValueProofs, decode: evidence.stateProof}},
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return errors.New("bundle must be a JSON object")
	}
	seen := make([]bool, len(fields))
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("invalid bundle field name")
		}
		var ignored discardedBundleValueJSON
		var target any = &ignored
		for i, field := range fields {
			// EqualFold also covers the Unicode aliases accepted by encoding/json.
			if !strings.EqualFold(name, field.name) {
				continue
			}
			if seen[i] {
				return fmt.Errorf("duplicate bundle field %q", field.name)
			}
			seen[i] = true
			target = field.target
			break
		}
		if err := d.Decode(target); err != nil {
			return err
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return errors.New("invalid bundle object terminator")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing bundle JSON data")
	}
	*b = decoded
	return nil
}

type bundleBufferedReferenceDecoder struct {
	target *HeaderBundle
	limits DecodeLimits
}

func (d *bundleBufferedReferenceDecoder) UnmarshalJSON(raw []byte) error {
	return unmarshalBundleBufferedReference(d.target, raw, d.limits)
}
func decodeBundleBufferedReference(raw []byte, limits DecodeLimits) (HeaderBundle, error) {
	var got HeaderBundle
	if err := json.Unmarshal(raw, &bundleBufferedReferenceDecoder{target: &got, limits: limits}); err != nil {
		return HeaderBundle{}, fmt.Errorf("parse bundle: %w", err)
	}
	if got.Version != WireVersion {
		return HeaderBundle{}, fmt.Errorf("unsupported wire version %d (expected %d)", got.Version, WireVersion)
	}
	return got, nil
}

func compareBundleFieldDecoders(t testing.TB, raw []byte, limits DecodeLimits) {
	t.Helper()
	got, err := unmarshalHeaderBundleJSON(raw, limits)
	want, oldErr := decodeBundleBufferedReference(raw, limits)
	if (err == nil) != (oldErr == nil) || !reflect.DeepEqual(got, want) {
		t.Fatalf("bundle projection or refusal differs: current=%v reference=%v", err, oldErr)
	}
	// Refusal classes, paths, budgets and privacy-safe error text stay stable.
	// Both decoders delegate scalar conversion to encoding/json.
	if err != nil && err.Error() != oldErr.Error() {
		t.Fatalf("bundle refusal text differs: current=%v reference=%v", err, oldErr)
	}
	var gotType, wantType *json.UnmarshalTypeError
	if errors.As(err, &gotType) != errors.As(oldErr, &wantType) || !reflect.DeepEqual(gotType, wantType) {
		t.Fatal("stdlib type-error details differ from the reference")
	}
	for _, decode := range []func(*HeaderBundle, []byte, DecodeLimits) error{
		(*HeaderBundle).unmarshalJSON, unmarshalBundleBufferedReference,
	} {
		before := sampleBundle()
		receiver := before
		directErr := decode(&receiver, raw, limits)
		if directErr != nil && !reflect.DeepEqual(receiver, before) {
			t.Fatal("failed direct decode changed the receiver")
		}
	}
}

func TestBundleFieldSpansMatchBufferedDecoder(t *testing.T) {
	for _, raw := range []string{
		emptyBundleJSON, " \n\t" + emptyBundleJSON + "\r\n", `{}`, `null`, `[]`, `1`, `"bundle"`, ``, `{`,
		`{"version":1,"chain_id":3,"headers":null,"commitments":[],"segments":null,"state_value_proofs":[]}`,
		`{"chain_id":3,"headers":[],"version":1}`,
		`{"ver\u0073ion":1,"HEADER\u017f":[],"extension":{"nested":[{"s":"\\\"{}[],:"},true,null,1e-9]},"extension":null}`,
		`{"extension":[null,false,-12.5e2,"\\\\",{"quote":"\"","brackets":"[{}]","unicode":"\ud800"}],"version":1}`,
		`{"version":1,"segments":[{"blocks":[null],"blocks":null}]}`,
		`{"version":1,"commitments":[{"flat":{"sorted_headers":[null]},"flat":null,"flat":{}}]}`,
		`{"version":1,"state_value_proofs":[{"proof_nodes":["AA==",null],"proof_nodes":null}]}`,
		`{"version":1,"version":null}`, `{"version":1,"VER\u0053ION":1}`,
		`{"headers":[],"headerſ":null,"version":1}`,
		`{"version":-1}`, `{"version":1,"chain_id":18446744073709551616}`,
		`{"version":1,"claimed_genesis":"bad"}`, `{"version":1,"headers":false}`,
		`{"version":1,"commitments":[{"flat":1}]}`,
		`{"version":1,"extension":[1,]}`, `{"version":1} {}`, `{"version":1,"extension":"unterminated}`,
		`{"extension":` + strings.Repeat("[", 10001) + `0` + strings.Repeat("]", 10001) + `,"version":1}`,
		"{\"\xff\":1,\"version\":1}",
	} {
		compareBundleFieldDecoders(t, []byte(raw), DecodeLimits{})
	}
	// Nested counters must not be refunded by duplicate/null fields or by a
	// failed earlier parse; excess rows refuse before decoding their sentinel.
	for _, tc := range []struct {
		raw    string
		limits DecodeLimits
	}{
		{`{"version":1,"headers":[null,null,"UNREACHED"]}`, DecodeLimits{MaxHeaders: 2}},
		{`{"version":1,"commitments":[null,null,"UNREACHED"]}`, DecodeLimits{MaxCommitments: 2}},
		{`{"version":1,"segments":[null,null,"UNREACHED"]}`, DecodeLimits{MaxSegments: 2}},
		{`{"version":1,"state_value_proofs":[null,null,"UNREACHED"]}`, DecodeLimits{MaxStateValueProofs: 2}},
		{`{"version":1,"commitments":[{"flat":{"sorted_headers":[null,null]},"flat":null},{"flat":{"sorted_headers":[null,"UNREACHED"]}}]}`, DecodeLimits{MaxFlatEvidenceMembers: 2, MaxTotalFlatEvidenceMembers: 3}},
		{`{"version":1,"segments":[{"blocks":[null,null],"BLOCKS":[null,"UNREACHED"]}]}`, DecodeLimits{MaxSegmentBlocks: 2, MaxTotalSegmentBlocks: 3}},
		{`{"version":1,"state_value_proofs":[{"proof_nodes":["AAAA","UNREACHED"]}]}`, DecodeLimits{MaxStateProofBytes: 2}},
		{`{"version":1,"segments":[{"blocks":[{"amount":"12345"}]}]}`, DecodeLimits{MaxAccountAmountBytes: 4}},
		{emptyBundleJSON, DecodeLimits{MaxTotalFlatEvidenceMembers: -1}},
	} {
		compareBundleFieldDecoders(t, []byte(tc.raw), tc.limits)
	}
}

func FuzzBundleFieldSpans(f *testing.F) {
	for _, raw := range []string{emptyBundleJSON, `{}`, `null`, `{"version":1,"extension":{"s":"\\\"{}[]"}}`,
		`{"version":1,"headers":[],"headerſ":null}`, `{"version":1,"commitments":[{"flat":{"sorted_headers":[null,null]}}]}`} {
		f.Add([]byte(raw), uint8(2))
	}
	f.Fuzz(func(t *testing.T, raw []byte, count uint8) {
		if len(raw) > 64<<10 {
			return
		}
		limit := int(count%16) + 1
		limits := DecodeLimits{MaxHeaders: limit, MaxCommitments: limit, MaxSegments: limit, MaxStateValueProofs: limit,
			MaxFlatEvidenceMembers: limit, MaxTotalFlatEvidenceMembers: limit, MaxSegmentBlocks: limit, MaxTotalSegmentBlocks: limit,
			MaxAccountAmountBytes: 64, MaxStateProofNodes: limit, MaxStateProofBytes: 256}
		compareBundleFieldDecoders(t, raw, limits)
	})
}

// Complete synthetic flat bundles repeat 1,000 members for every target, as
// current wire evidence does. Preparation and reference/projection checks are
// excluded; these observations measure JSON allocations, not proof validity,
// RSS, network performance, sustainable throughput or a consumer service level.
func BenchmarkProofBundleFieldSpans(b *testing.B) {
	members := make([]chain.AccountHeader, 1000)
	for i := range members {
		members[i] = chain.AccountHeader{Height: uint64(i + 1), Hash: chain.Hash{byte(i), byte(i >> 8)}}
	}
	for _, targets := range []int{1, 16, 256} {
		bundle := HeaderBundle{Version: 1, ChainID: 99, Commitments: make([]CommitmentEvidence, targets)}
		for i := range bundle.Commitments {
			bundle.Commitments[i] = CommitmentEvidence{Height: 10001, Target: members[i*999/max(1, targets-1)], Flat: &FlatContentEvidence{SortedHeaders: members}}
		}
		raw, err := json.Marshal(bundle)
		if err != nil {
			b.Fatal(err)
		}
		limits := DecodeLimits{MaxCommitments: targets, MaxFlatEvidenceMembers: 1000, MaxTotalFlatEvidenceMembers: targets * 1000}
		for _, mode := range []struct {
			name   string
			decode func([]byte, DecodeLimits) (HeaderBundle, error)
		}{
			{"buffered_reference", decodeBundleBufferedReference}, {"borrowed_fields", unmarshalHeaderBundleJSON},
		} {
			b.Run(fmt.Sprintf("targets_%d/%s", targets, mode.name), func(b *testing.B) {
				got, err := mode.decode(raw, limits)
				if err != nil || !reflect.DeepEqual(got, bundle) {
					b.Fatalf("benchmark projection differs: %v", err)
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				b.ResetTimer()
				for range b.N {
					got, err := mode.decode(raw, limits)
					if err != nil || len(got.Commitments) != targets || len(got.Commitments[targets-1].Flat.SortedHeaders) != 1000 || got.Commitments[targets-1].Target != bundle.Commitments[targets-1].Target {
						b.Fatal("benchmark decode failed")
					}
				}
			})
		}
	}
}
