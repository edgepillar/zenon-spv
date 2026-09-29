package main

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/0x3639/zenon-spv/internal/proof"
)

// encodeBundleBounded accumulates at most maxBytes of compact wire JSON,
// including the final newline. Encoding one item at a time avoids expanding
// repeated flat evidence into an unbounded temporary encoding/json buffer.
// It is an output bound, not a process-wide memory limit: source objects and
// encoding/json's per-item scratch allocations are additional memory.
func encodeBundleBounded(b proof.HeaderBundle, maxBytes int64) ([]byte, error) {
	return encodeBundleWithSegments(b, maxBytes, len(b.Segments), func(i int) (proof.AccountSegment, error) {
		return b.Segments[i], nil
	})
}

// encodeBundleWithSegments replaces b.Segments with lazily loaded segments.
// Each segment is encoded before requesting the next one. It retains no decoded
// segments across calls and stops loading on any encoding or source error.
// Headers and commitments consume the same byte budget before the first load.
func encodeBundleWithSegments(b proof.HeaderBundle, maxBytes int64, segmentCount int, loadSegment func(int) (proof.AccountSegment, error)) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("bundle output byte limit must be positive")
	}
	w := boundedJSON{limit: maxBytes}
	w.raw(`{"version":`)
	w.value(b.Version)
	w.raw(`,"chain_id":`)
	w.value(b.ChainID)
	w.raw(`,"claimed_genesis":`)
	w.value(b.ClaimedGenesis)
	w.raw(`,"headers":`)
	w.array(len(b.Headers), b.Headers == nil, func(i int) { w.value(b.Headers[i]) })
	if len(b.Commitments) > 0 {
		w.raw(`,"commitments":`)
		w.array(len(b.Commitments), false, func(i int) { w.value(b.Commitments[i]) })
	}
	if segmentCount > 0 {
		w.raw(`,"segments":`)
		w.array(segmentCount, false, func(i int) {
			s, err := loadSegment(i)
			if err != nil {
				w.err = err
				return
			}
			w.raw(`{"address":`)
			w.value(s.Address)
			w.raw(`,"blocks":`)
			w.array(len(s.Blocks), s.Blocks == nil, func(j int) { w.value(s.Blocks[j]) })
			w.raw(`}`)
		})
	}
	if len(b.StateValueProofs) > 0 {
		w.raw(`,"state_value_proofs":`)
		w.array(len(b.StateValueProofs), false, func(i int) { w.value(b.StateValueProofs[i]) })
	}
	w.raw("}\n")
	if w.err != nil {
		return nil, w.err
	}
	return w.buf.Bytes(), nil
}

type boundedJSON struct {
	buf   bytes.Buffer
	limit int64
	err   error
}

func (w *boundedJSON) raw(s string) {
	if w.err != nil {
		return
	}
	if int64(len(s)) > w.limit-int64(w.buf.Len()) {
		w.err = proof.ErrBundleTooLarge
		return
	}
	w.buf.WriteString(s)
}

func (w *boundedJSON) value(v any) {
	if w.err != nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		w.err = err
		return
	}
	w.raw(string(b))
}

func (w *boundedJSON) array(n int, isNil bool, item func(int)) {
	if isNil {
		w.raw("null")
		return
	}
	w.raw("[")
	for i := 0; i < n && w.err == nil; i++ {
		if i > 0 {
			w.raw(",")
		}
		if w.err == nil {
			item(i)
		}
	}
	w.raw("]")
}
