package proof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Synthetic unused metadata isolates complete bundle JSON decoding. Inputs are
// built outside timing. Both modes retain identical known fields and apply the
// same decode limits; this is not a verified proof or a network/RSS workload.
func BenchmarkProofBundleExtensions(b *testing.B) {
	for _, size := range []int{32 << 10, 1 << 20, 8 << 20} {
		raw := []byte(`{"extension":{"metadata":"` + strings.Repeat("x", size) + `"},` + emptyBundleJSON[1:])
		limits := DecodeLimits{MaxHeaders: 1, MaxCommitments: 1, MaxSegments: 1, MaxStateValueProofs: 1,
			MaxFlatEvidenceMembers: 1, MaxTotalFlatEvidenceMembers: 1, MaxSegmentBlocks: 1, MaxTotalSegmentBlocks: 1,
			MaxAccountAmountBytes: DefaultMaxAccountAmountBytes, MaxStateProofNodes: 1, MaxStateProofBytes: 1}
		for _, mode := range []struct {
			name   string
			decode func([]byte, DecodeLimits) (HeaderBundle, error)
		}{
			{"copy_reference", decodeBundleCopyReference}, {"discard_extension", unmarshalHeaderBundleJSON},
		} {
			b.Run(fmt.Sprintf("%d/%s", size, mode.name), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					got, err := mode.decode(raw, limits)
					if err != nil || got.Version != 1 || got.ChainID != 3 || got.ClaimedGenesis != (HeaderBundle{}).ClaimedGenesis ||
						got.Headers == nil || len(got.Headers) != 0 || got.Commitments == nil || len(got.Commitments) != 0 ||
						got.Segments == nil || len(got.Segments) != 0 || got.StateValueProofs == nil || len(got.StateValueProofs) != 0 {
						b.Fatalf("known bundle projection changed: %v", err)
					}
				}
			})
		}
	}
}

type bundleCopyReferenceDecoder struct {
	target *HeaderBundle
	limits DecodeLimits
}

func (decoder *bundleCopyReferenceDecoder) UnmarshalJSON(raw []byte) error {
	return unmarshalBundleCopyReference(decoder.target, raw, decoder.limits)
}
func decodeBundleCopyReference(raw []byte, limits DecodeLimits) (HeaderBundle, error) {
	var bundle HeaderBundle
	if err := json.Unmarshal(raw, &bundleCopyReferenceDecoder{target: &bundle, limits: limits}); err != nil {
		return HeaderBundle{}, fmt.Errorf("parse bundle: %w", err)
	}
	if bundle.Version != WireVersion {
		return HeaderBundle{}, fmt.Errorf("unsupported wire version %d (expected %d)", bundle.Version, WireVersion)
	}
	return bundle, nil
}

// Exact helper body from 2cc184907fc2a01154709ec293cd72281c04ff5b, with only
// the receiver signature adapted. This reference is compiled only in tests.
func unmarshalBundleCopyReference(b *HeaderBundle, raw []byte, limits DecodeLimits) error {
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
		var ignored json.RawMessage
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
