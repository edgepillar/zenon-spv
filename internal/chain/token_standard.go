package chain

import (
	"encoding/hex"
	"errors"
)

// TokenStandardSize matches types.ZenonTokenStandardSize at
// reference/go-zenon/common/types/tokenstandard.go:14.
const TokenStandardSize = 10

// TokenStandard is the 10-byte ZTS identifier used in AccountBlock.
//
// On the wire (in HeaderBundle JSON) we use hex for uniformity with
// chain.Hash and chain.Address. Bech32 ("zts1...") is the canonical
// user-facing form; an encoder for it isn't strictly required by the
// verifier, so it's deferred until a concrete CLI ergonomics need.
type TokenStandard [TokenStandardSize]byte

// Bytes returns a slice view of t. The returned slice aliases t.
func (t TokenStandard) Bytes() []byte { return t[:] }

// MarshalText emits TokenStandard as a lowercase hex string.
func (t TokenStandard) MarshalText() ([]byte, error) {
	text := make([]byte, 2*TokenStandardSize)
	hex.Encode(text, t[:])
	return text, nil
}

// UnmarshalText accepts a hex string with optional 0x prefix.
func (t *TokenStandard) UnmarshalText(text []byte) error {
	if len(text) >= 2 && text[0] == '0' && text[1] == 'x' {
		text = text[2:]
	}
	if len(text) != 2*TokenStandardSize {
		return errors.New("chain.TokenStandard: invalid hex length")
	}
	// Commit only a complete value; hex.Decode may write before failing.
	var decoded TokenStandard
	if _, err := hex.Decode(decoded[:], text); err != nil {
		return err
	}
	*t = decoded
	return nil
}
