package proof

import (
	"fmt"
	"io"
	"math"
)

// This bounds eager allocation from metadata, not the accepted input size.
// Larger or unusable hints fall back to the existing incremental reader.
// The extra EOF-probe byte and int conversion also fit on 32-bit platforms.
const maxBundleReadHintBytes = 64 << 20

func readBundleBytes(r io.Reader, maxBytes, sizeHint int64) ([]byte, error) {
	src := r
	if maxBytes > 0 {
		readLimit := maxBytes
		if readLimit < math.MaxInt64 {
			readLimit++
		}
		src = io.LimitReader(r, readLimit)
	}
	var raw []byte
	var err error
	if maxBytes > 0 && sizeHint > 0 && sizeHint <= maxBytes && sizeHint <= maxBundleReadHintBytes {
		raw, err = readHintedBundleBytes(src, int(sizeHint)+1)
	} else {
		raw, err = io.ReadAll(src)
	}
	// A non-EOF read error wins even when its bytes include the overflow
	// probe or a complete JSON document. No partial bytes reach decoding.
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	if maxBytes > 0 && int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("%w: max=%d bytes, file is at least %d bytes",
			ErrBundleTooLarge, maxBytes, len(raw))
	}
	return raw, nil
}

func readHintedBundleBytes(r io.Reader, capacity int) ([]byte, error) {
	raw := make([]byte, 0, capacity)
	for len(raw) < cap(raw) {
		n, err := r.Read(raw[len(raw):cap(raw)])
		raw = raw[:len(raw)+n]
		if err == io.EOF {
			return raw, nil
		}
		if err != nil {
			return nil, err
		}
	}
	// The file outgrew its hint. Continue through the same limited reader;
	// the size hint must never truncate data or hide a later read error.
	rest, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return append(raw, rest...), nil
}
