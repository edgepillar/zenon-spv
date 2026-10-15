package chain

import (
	"encoding/hex"
	"errors"
)

// MarshalText emits Hash as a lowercase hex string for human-readable
// JSON fixtures and CLI output. Implements encoding.TextMarshaler.
func (h Hash) MarshalText() ([]byte, error) {
	text := make([]byte, 2*HashSize)
	hex.Encode(text, h[:])
	return text, nil
}

// UnmarshalText accepts a hex string with optional 0x prefix.
// Implements encoding.TextUnmarshaler.
func (h *Hash) UnmarshalText(text []byte) error {
	if len(text) >= 2 && text[0] == '0' && text[1] == 'x' {
		text = text[2:]
	}
	if len(text) != 2*HashSize {
		return errors.New("chain.Hash: invalid hex length")
	}
	// Do not expose a partially decoded prefix when hex.Decode rejects a digit.
	var decoded Hash
	if _, err := hex.Decode(decoded[:], text); err != nil {
		return err
	}
	*h = decoded
	return nil
}
