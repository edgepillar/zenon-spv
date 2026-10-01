package main

import (
	"encoding/hex"
	"errors"
	"flag"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// An explicitly empty pin is invalid; it must not turn a requested guard off.
// Use a string flag so the flag parser never echoes a malformed private value.
func parseContextPin(fs *flag.FlagSet, raw string) (*chain.Hash, error) {
	present := false
	fs.Visit(func(f *flag.Flag) { present = present || f.Name == "expect-context" })
	if !present {
		return nil, nil
	}
	var hash chain.Hash
	if len(raw) != hex.EncodedLen(len(hash)) {
		return nil, errors.New("--expect-context requires a 64-character hexadecimal fingerprint")
	}
	if _, err := hex.Decode(hash[:], []byte(raw)); err != nil {
		return nil, errors.New("--expect-context requires a 64-character hexadecimal fingerprint")
	}
	return &hash, nil
}
