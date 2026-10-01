package main

import (
	"errors"
	"flag"
	"strconv"

	"github.com/0x3639/zenon-spv/internal/verify"
)

func configureRetention(fs *flag.FlagSet, raw string, policy *verify.Policy) error {
	present := false
	fs.Visit(func(f *flag.Flag) { present = present || f.Name == "retain-headers" })
	if !present {
		return nil
	}
	k, err := strconv.Atoi(raw)
	if err != nil || k < 1 {
		return errors.New("--retain-headers requires an integer K greater than W and at most 4096")
	}
	policy.RetainHeaders = k
	return policy.ValidateRetention()
}
