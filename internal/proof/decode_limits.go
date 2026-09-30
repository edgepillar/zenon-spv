package proof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// DecodeLimits caps top-level array allocation while reading a bundle. Zero
// disables a count cap. Nested evidence and aggregate work still require the
// verifier's policy preflight; these are not total process memory limits.
type DecodeLimits struct {
	MaxHeaders          int
	MaxCommitments      int
	MaxSegments         int
	MaxStateValueProofs int
}

func (limits DecodeLimits) validate() error {
	if limits.MaxHeaders < 0 || limits.MaxCommitments < 0 || limits.MaxSegments < 0 || limits.MaxStateValueProofs < 0 {
		return errors.New("bundle decode count limits must be nonnegative")
	}
	return nil
}

// BundleCountLimitError identifies a count refusal without exposing input
// values. Field is one of the four canonical top-level array field names.
type BundleCountLimitError struct {
	Field string
	Limit int
}

func (err *BundleCountLimitError) Error() string {
	return fmt.Sprintf("bundle %s count exceeds limit %d", err.Field, err.Limit)
}

type bundleRows[T any] struct {
	target *[]T
	field  string
	limit  int
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
		for d.More() {
			if rows.limit > 0 && len(decoded) >= rows.limit {
				return &BundleCountLimitError{Field: rows.field, Limit: rows.limit}
			}
			var row T
			if err := d.Decode(&row); err != nil {
				return err
			}
			decoded = append(decoded, row)
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
