package main

import (
	"io"
	"os"
)

// The validated descriptor size is an allocation hint, never an input boundary.
// Read to EOF through at most one overflow byte even if the file changed size.
// The fixed consumer maximum keeps capacities and doubling safe on 32-bit Go.
func readInputBytes(r io.Reader, limit, sizeHint int64) ([]byte, error) {
	if limit < 0 || limit > maxReportBytes {
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
		// A complete document or overflow probe cannot hide a read failure.
		// Preserve the consumer's fixed error without exposing partial bytes.
		if err != nil && err != io.EOF || int64(len(raw)) > limit {
			return nil, os.ErrInvalid
		}
		if err == io.EOF {
			return raw, nil
		}
		if len(raw) == cap(raw) {
			grown := make([]byte, len(raw), min(capacityLimit, cap(raw)*2))
			copy(grown, raw)
			raw = grown
		}
	}
}
