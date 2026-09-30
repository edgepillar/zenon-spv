package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Tiny JSON elements can expand into large header structs. Enforce the count
// limit while decoding, before retained-state validation or policy truncation.
type retainedHeaderWindow []chain.Header

func (window *retainedHeaderWindow) UnmarshalJSON(raw []byte) error {
	decoded, err := decodeRetainedWindow(raw, MaxPersistedHeaders)
	if err != nil {
		return err
	}
	*window = decoded
	return nil
}

func decodeRetainedWindow(raw []byte, maxHeaders int) ([]chain.Header, error) {
	if maxHeaders < 0 {
		return nil, fmt.Errorf("%w: negative header count limit", ErrInvalidRetainedState)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil {
		return nil, err
	}
	var decoded []chain.Header
	if first != nil {
		if first != json.Delim('[') {
			return nil, errors.New("retained window: expected an array or null")
		}
		// Preserve the distinction between [] and null in saved-state round trips.
		decoded = make([]chain.Header, 0)
		for d.More() {
			if len(decoded) >= maxHeaders {
				return nil, fmt.Errorf("%w: retained header count exceeds persistence limit", ErrInvalidRetainedState)
			}
			var header chain.Header
			if err := d.Decode(&header); err != nil {
				return nil, err
			}
			decoded = append(decoded, header)
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
	}
	var extra json.RawMessage
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			err = errors.New("retained window: trailing JSON value")
		}
		return nil, err
	}
	return decoded, nil
}
