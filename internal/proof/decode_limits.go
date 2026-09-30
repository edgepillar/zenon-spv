package proof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// DecodeLimits caps array counts and decoded proof-node bytes while reading a
// bundle. Zero disables a cap. Other byte fields, JSON input buffers, and
// cryptographic work still need separate bounds; these are not total process
// memory limits.
type DecodeLimits struct {
	MaxHeaders                  int
	MaxCommitments              int
	MaxSegments                 int
	MaxStateValueProofs         int
	MaxFlatEvidenceMembers      int
	MaxTotalFlatEvidenceMembers int
	MaxSegmentBlocks            int
	MaxTotalSegmentBlocks       int
	MaxStateProofNodes          int
	MaxStateProofBytes          int
}

func (limits DecodeLimits) validate() error {
	if limits.MaxHeaders < 0 || limits.MaxCommitments < 0 || limits.MaxSegments < 0 || limits.MaxStateValueProofs < 0 ||
		limits.MaxFlatEvidenceMembers < 0 || limits.MaxTotalFlatEvidenceMembers < 0 ||
		limits.MaxSegmentBlocks < 0 || limits.MaxTotalSegmentBlocks < 0 || limits.MaxStateProofNodes < 0 || limits.MaxStateProofBytes < 0 {
		return errors.New("bundle decode limits must be nonnegative")
	}
	return nil
}

// BundleCountLimitError identifies a count refusal without exposing input
// values. Field is a canonical array path or an aggregate-count identifier.
type BundleCountLimitError struct {
	Field string
	Limit int
}

func (err *BundleCountLimitError) Error() string {
	return fmt.Sprintf("bundle %s count exceeds limit %d", err.Field, err.Limit)
}

// BundleByteLimitError identifies a decoded-byte refusal without exposing
// input values. Field is the canonical path of the bounded byte collection.
type BundleByteLimitError struct {
	Field string
	Limit int
}

func (err *BundleByteLimitError) Error() string {
	return fmt.Sprintf("bundle %s bytes exceed limit %d", err.Field, err.Limit)
}

type bundleRows[T any] struct {
	target *[]T
	field  string
	limit  int
	budget *rowBudget
	decode func(*json.Decoder, *T) error
}

func (rows *bundleRows[T]) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil {
		return err
	}
	var decoded []T
	if first != nil {
		if first != json.Delim('[') {
			return fmt.Errorf("bundle %s must be an array or null", rows.field)
		}
		decoded = make([]T, 0)
		decode := rows.decode
		if decode == nil {
			decode = func(d *json.Decoder, row *T) error { return d.Decode(row) }
		}
		for d.More() {
			if rows.limit > 0 && len(decoded) >= rows.limit {
				return &BundleCountLimitError{Field: rows.field, Limit: rows.limit}
			}
			if rows.budget != nil && rows.budget.remaining == 0 {
				return &BundleCountLimitError{Field: rows.budget.field, Limit: rows.budget.limit}
			}
			var row T
			if err := decode(d, &row); err != nil {
				return err
			}
			decoded = append(decoded, row)
			if rows.budget != nil {
				rows.budget.remaining--
			}
		}
		if _, err := d.Token(); err != nil {
			return err
		}
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("bundle %s has trailing JSON data", rows.field)
	}
	*rows.target = decoded
	return nil
}
