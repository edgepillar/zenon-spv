package proof

import (
	"encoding/json"
	"errors"
	"fmt"
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
	// Validate complete syntax and nesting before borrowing any value spans.
	var syntax discardedBundleValueJSON
	if err := json.Unmarshal(raw, &syntax); err != nil {
		return err
	}
	cursor := bundleValueCursor{raw: raw}
	cursor.space()
	if cursor.raw[cursor.at] != '{' {
		return errors.New("bundle must be a JSON object")
	}
	cursor.at++
	seen := make([]bool, len(fields))
	for {
		cursor.space()
		if cursor.raw[cursor.at] == '}' {
			break
		}
		start := cursor.at
		cursor.string()
		var name string
		if err := json.Unmarshal(raw[start:cursor.at], &name); err != nil {
			return err
		}
		cursor.space()
		cursor.at++ // Colon; complete-document validation has checked the grammar.
		cursor.space()
		start = cursor.at
		cursor.value()
		var target any
		for i, field := range fields {
			// Preserve Unicode aliases as well as ASCII case matching.
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
		if target != nil {
			if err := json.Unmarshal(raw[start:cursor.at], target); err != nil {
				return err
			}
		}
		cursor.space()
		if cursor.raw[cursor.at] == '}' {
			break
		}
		cursor.at++ // Comma; the next validated token is another field name.
	}
	*b = decoded
	return nil
}

// encoding/json validates complete syntax and maximum nesting before invoking
// this no-retention callback. It supplies no projection or semantic evidence;
// known-field binding and duplicate/resource guards remain in the caller.
type discardedBundleValueJSON struct{}

func (*discardedBundleValueJSON) UnmarshalJSON([]byte) error { return nil }

// bundleValueCursor borrows encoded value spans only after encoding/json has
// validated the entire document. Scalar decoding and all nested count/byte
// budgets remain owned by the existing field decoders.
type bundleValueCursor struct {
	raw []byte
	at  int
}

func (c *bundleValueCursor) space() {
	for c.at < len(c.raw) {
		switch c.raw[c.at] {
		case ' ', '\t', '\r', '\n':
			c.at++
		default:
			return
		}
	}
}

func (c *bundleValueCursor) string() {
	c.at++
	for {
		switch c.raw[c.at] {
		case '\\':
			c.at += 2
		case '"':
			c.at++
			return
		default:
			c.at++
		}
	}
}

func (c *bundleValueCursor) value() {
	switch c.raw[c.at] {
	case '"':
		c.string()
	case '[', '{':
		depth := 1
		c.at++
		for depth > 0 {
			switch c.raw[c.at] {
			case '"':
				c.string()
				continue
			case '[', '{':
				depth++
			case ']', '}':
				depth--
			}
			c.at++
		}
	default:
		for c.at < len(c.raw) {
			switch c.raw[c.at] {
			case ' ', '\t', '\r', '\n', ',', ']', '}':
				return
			default:
				c.at++
			}
		}
	}
}
