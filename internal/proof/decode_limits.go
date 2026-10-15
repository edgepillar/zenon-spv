package proof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// DecodeLimits caps array counts, decoded proof-node bytes, and account-amount
// JSON token bytes while reading a bundle. Zero disables a cap. Other byte
// fields, JSON input buffers, and cryptographic work still need separate bounds;
// these are not total process memory limits.
type DecodeLimits struct {
	MaxHeaders                  int
	MaxCommitments              int
	MaxSegments                 int
	MaxStateValueProofs         int
	MaxFlatEvidenceMembers      int
	MaxTotalFlatEvidenceMembers int
	MaxSegmentBlocks            int
	MaxTotalSegmentBlocks       int
	MaxAccountAmountBytes       int
	MaxStateProofNodes          int
	MaxStateProofBytes          int
}

func (limits DecodeLimits) validate() error {
	if limits.MaxHeaders < 0 || limits.MaxCommitments < 0 || limits.MaxSegments < 0 || limits.MaxStateValueProofs < 0 ||
		limits.MaxFlatEvidenceMembers < 0 || limits.MaxTotalFlatEvidenceMembers < 0 ||
		limits.MaxSegmentBlocks < 0 || limits.MaxTotalSegmentBlocks < 0 || limits.MaxAccountAmountBytes < 0 ||
		limits.MaxStateProofNodes < 0 || limits.MaxStateProofBytes < 0 {
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

// BundleByteLimitError identifies a byte refusal without exposing input
// values. Field is the canonical path of the bounded byte collection or token.
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
	// An optional private storage hint cannot authorize rows or consume budget.
	capacityHint func(contents []byte, ceiling int) int
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
		capacity := 0
		if rows.capacityHint != nil {
			ceiling := int(^uint(0) >> 1)
			if rows.limit > 0 {
				ceiling = rows.limit
			}
			if rows.budget != nil {
				ceiling = min(ceiling, rows.budget.remaining)
			}
			capacity = max(0, min(ceiling, rows.capacityHint(raw[d.InputOffset():], ceiling)))
		}
		decoded = make([]T, 0, capacity)
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
			// Decode into a fresh owned slice slot instead of making each row
			// escape separately through the callback. Neither the slice nor a
			// partially decoded slot reaches the receiver on failure.
			decoded = append(decoded, row)
			if err := decode(d, &decoded[len(decoded)-1]); err != nil {
				return err
			}
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

const flatCapacityMaxRows = 100_000
const flatCapacityWireBytes = 128

// flatRowsCapacityHint only suggests storage for account-header rows. At most
// 100,000 slots and one slot per 128 encoded bytes can be reserved, further
// capped by the caller's remaining array/aggregate allowance. An account header
// occupies at most 64 bytes on supported Go platforms, so the requested initial
// row capacity uses at most half the contents length, excluding allocator and
// metadata overhead. Sparse/short encodings can still grow normally; this hint
// is neither a count nor a process-memory limit.
func flatRowsCapacityHint(contents []byte, ceiling int) int {
	ceiling = min(ceiling, flatCapacityMaxRows, len(contents)/flatCapacityWireBytes)
	if ceiling <= 0 {
		return 0
	}
	count, depth := 0, 0
	inString, inValue := false, false
	for index := 0; index < len(contents); index++ {
		value := contents[index]
		if inString {
			// Most account-header bytes are unescaped hash/address text. Skip
			// those spans without branching over every byte. Backslash parity
			// only decides whether a found quote closes this string.
			next := bytes.IndexByte(contents[index:], '"')
			if next < 0 {
				return count
			}
			index += next
			escaped := false
			for before := index - 1; before >= 0 && contents[before] == '\\'; before-- {
				escaped = !escaped
			}
			inString = escaped
			continue
		}
		if depth == 0 {
			switch value {
			case ' ', '\t', '\r', '\n':
				continue
			case ']':
				return count
			case ',':
				inValue = false
				continue
			}
			if !inValue {
				count++
				if count == ceiling {
					return count
				}
				inValue = true
			}
		}
		switch value {
		case '"':
			inString = true
		case '[', '{':
			depth++
		case ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	// Malformed/incomplete input can yield a smaller or larger hint, within
	// the same bounds. The original JSON decoder still owns every syntax,
	// type, trailing-input, count and byte refusal, in its original order.
	return count
}
