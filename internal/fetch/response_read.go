package fetch

import "io"

// readRPCBody keeps buffer growth within the call's remaining byte budget and
// one overflow probe. The caller supplies a budget from 0 to MaxResponseBytes;
// this fixed maximum also makes growth and int conversion safe on 32-bit Go.
// No Content-Length or other peer metadata is used as an allocation hint.
// Size refusal and error formatting remain the caller's responsibility.
func readRPCBody(r io.Reader, maxBytes int64) ([]byte, error) {
	limit := int(maxBytes) + 1
	src := io.LimitReader(r, maxBytes+1)
	raw := make([]byte, 0, min(512, limit))
	for {
		n, err := src.Read(raw[len(raw):cap(raw)])
		raw = raw[:len(raw)+n]
		if err != nil {
			if err == io.EOF {
				return raw, nil
			}
			// Preserve a simultaneous data/error result, including an overflow
			// probe. The caller must reject it before interpreting any bytes.
			return raw, err
		}
		if len(raw) == cap(raw) && cap(raw) < limit {
			grown := make([]byte, len(raw), min(limit, cap(raw)+max(1, cap(raw)/2)))
			copy(grown, raw)
			raw = grown
		}
	}
}
