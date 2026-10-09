package main

import (
	"encoding/hex"
	"errors"
	"flag"

	"github.com/0x3639/zenon-spv/internal/chain"
)

type contextPinFlag struct {
	raw      string
	supplied bool
	repeated bool
}

func registerContextPin(fs *flag.FlagSet) *contextPinFlag {
	value := new(contextPinFlag)
	fs.Var(value, "expect-context", "require this 64-hex verification context fingerprint (at most once)")
	return value
}

// Neither usage nor flag parsing may echo a supplied private value. Defer
// validation until parsing finishes so JSON commands retain their framing.
func (*contextPinFlag) String() string { return "" }

func (value *contextPinFlag) Set(raw string) error {
	if value.supplied {
		value.repeated = true
	} else {
		value.supplied, value.raw = true, raw
	}
	return nil
}

// An empty or repeated pin must not turn a requested guard off or replace it.
func parseContextPin(value *contextPinFlag) (*chain.Hash, error) {
	if value.repeated {
		return nil, errors.New("--expect-context must occur at most once")
	}
	if !value.supplied {
		return nil, nil
	}
	var hash chain.Hash
	if len(value.raw) != hex.EncodedLen(len(hash)) {
		return nil, errors.New("--expect-context requires a 64-character hexadecimal fingerprint")
	}
	if _, err := hex.Decode(hash[:], []byte(value.raw)); err != nil {
		return nil, errors.New("--expect-context requires a 64-character hexadecimal fingerprint")
	}
	return &hash, nil
}
