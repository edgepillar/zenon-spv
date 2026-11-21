package verify

import (
	"fmt"
	"io"
)

// Remember the first terminal result. A JSON decoder can consume bytes from
// the same read as an I/O error and still return a complete JSON token.
type boundedStateInput struct {
	reader io.LimitedReader
	err    error
}

func (r *boundedStateInput) Read(raw []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.reader.Read(raw)
	r.err = err
	return n, err
}

// A stat size is an allocation hint, never the input boundary. Read to EOF
// even when the file grew or shrank, and inspect at most maxBytes+1 bytes.
// The common stable-file path needs one input buffer. Its capacity, including
// any growth, stays within the byte limit plus its single overflow probe.
func readStateBytes(r io.Reader, maxBytes, sizeHint int64) ([]byte, error) {
	if maxBytes < 0 || maxBytes > MaxStateFileBytes {
		return nil, fmt.Errorf("%w: invalid state byte limit", ErrInvalidRetainedState)
	}
	// The fixed persistence maximum also makes these conversions and doubling
	// safe on 32-bit platforms. Ignore unusable hints without changing the cap.
	limit := int(maxBytes) + 1
	initial := min(512, limit)
	if sizeHint > 0 && sizeHint <= maxBytes {
		initial = max(initial, int(sizeHint)+1)
	}
	raw := make([]byte, 0, initial)
	for {
		n, err := r.Read(raw[len(raw):cap(raw)])
		raw = raw[:len(raw)+n]
		// Preserve non-EOF errors even when a read fills the buffer or supplies
		// the overflow byte. No partial bytes may become a decoded state.
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("read: %w", err)
		}
		if len(raw) > int(maxBytes) {
			return nil, ErrStateFileTooLarge
		}
		if err == io.EOF {
			return raw, nil
		}
		if len(raw) == cap(raw) {
			grown := make([]byte, len(raw), min(limit, cap(raw)*2))
			copy(grown, raw)
			raw = grown
		}
	}
}
