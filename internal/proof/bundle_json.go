package proof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// UnmarshalJSON preserves the existing field matching and unknown-field
// compatibility, but rejects repeated top-level bundle fields. Later arrays or
// nulls must not hide earlier evidence from resource or query-mode checks.
// The receiver changes only after the complete object has decoded successfully.
func (b *HeaderBundle) UnmarshalJSON(raw []byte) error {
	return b.unmarshalJSON(raw, DecodeLimits{})
}

func (b *HeaderBundle) unmarshalJSON(raw []byte, limits DecodeLimits) error {
	if err := limits.validate(); err != nil {
		return err
	}
	var decoded HeaderBundle
	fields := []struct {
		name   string
		target any
	}{
		{"version", &decoded.Version}, {"chain_id", &decoded.ChainID},
		{"claimed_genesis", &decoded.ClaimedGenesis},
		{"headers", &bundleRows[chain.Header]{&decoded.Headers, "headers", limits.MaxHeaders}},
		{"commitments", &bundleRows[CommitmentEvidence]{&decoded.Commitments, "commitments", limits.MaxCommitments}},
		{"segments", &bundleRows[AccountSegment]{&decoded.Segments, "segments", limits.MaxSegments}},
		{"state_value_proofs", &bundleRows[StateValueProof]{&decoded.StateValueProofs, "state_value_proofs", limits.MaxStateValueProofs}},
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
