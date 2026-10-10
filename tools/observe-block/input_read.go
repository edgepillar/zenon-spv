package main

import (
	"io"
	"os"
)

// The validated descriptor size is only an allocation hint. Read the complete
// input or one overflow byte even after a size change. Keep the previous raw
// byte/read-error result; the caller refuses failed or oversized snapshots.
// The fixed maximum keeps capacities and doubling safe on 32-bit Go.
func readExpectationBytes(r io.Reader, limit, sizeHint int64) ([]byte, error) {
	if limit < 0 || limit > maxExpectationsBytes {
		return nil, os.ErrInvalid
	}
	capacityLimit := int(limit) + 1
	initial := min(512, capacityLimit)
	if sizeHint > 0 && sizeHint <= limit {
		initial = max(initial, int(sizeHint)+1)
	}
	raw := make([]byte, 0, initial)
	for {
		n, err := r.Read(raw[len(raw):cap(raw)])
		raw = raw[:len(raw)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return raw, err
		}
		if len(raw) == capacityLimit {
			return raw, nil
		}
		if len(raw) == cap(raw) {
			grown := make([]byte, len(raw), min(capacityLimit, cap(raw)*2))
			copy(grown, raw)
			raw = grown
		}
	}
}
