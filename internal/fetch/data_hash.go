package fetch

import (
	"encoding/base64"
	"io"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Small inputs keep the existing direct decode. For larger valid inputs, only
// a fixed scratch buffer is needed to hash the locally decoded preimage. The
// encoded string and RPC response are still governed by their existing bounds.
const rpcDataStreamThreshold = 4 << 10

func hashRPCData(encoded string) (chain.Hash, error) {
	if len(encoded) <= rpcDataStreamThreshold {
		return bufferedRPCDataHash(encoded)
	}
	// NewDecoder can decode separately padded blocks across read boundaries,
	// unlike DecodeString. No alphabet character may follow the first padding
	// character. Delegate suspect tails to the original whole-value decoder.
	if padding := strings.IndexByte(encoded, '='); padding >= 0 {
		for i := padding + 1; i < len(encoded); i++ {
			if c := encoded[i]; c != '=' && c != '\r' && c != '\n' {
				return bufferedRPCDataHash(encoded)
			}
		}
	}
	h := sha3.New256()
	var scratch [3 << 10]byte
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded))
	if _, err := io.CopyBuffer(h, decoder, scratch[:]); err != nil {
		// Streaming errors have different offsets and EOF types. Preserve the
		// original decoder's exact error and discard every partial hash. This
		// fallback retains the old allocation behavior on malformed inputs.
		return bufferedRPCDataHash(encoded)
	}
	var result chain.Hash
	copy(result[:], h.Sum(result[:0]))
	return result, nil
}

func bufferedRPCDataHash(encoded string) (chain.Hash, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return chain.Hash{}, err
	}
	return sha3sum(raw), nil
}
