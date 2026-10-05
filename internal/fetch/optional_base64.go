package fetch

import (
	"encoding/base64"
	"strings"
)

const optionalBase64SizingThreshold = 4096

// base64ToBytesOptional decodes optional RPC public keys and signatures.
// Ordinary fields retain DecodeString's path. For large fields, ignored CR/LF
// bytes do not inflate the output allocation. The original input still reaches
// the standard decoder, preserving partial bytes and corruption offsets.
// This is an allocation choice, not a signature-size or transport policy.
func base64ToBytesOptional(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	if len(s) <= optionalBase64SizingThreshold {
		return base64.StdEncoding.DecodeString(s)
	}
	encodedBytes := len(s) - strings.Count(s, "\r") - strings.Count(s, "\n")
	if encodedBytes == len(s) {
		return base64.StdEncoding.DecodeString(s)
	}
	out := make([]byte, base64.StdEncoding.DecodedLen(encodedBytes))
	n, err := base64.StdEncoding.Decode(out, []byte(s))
	return out[:n], err
}
