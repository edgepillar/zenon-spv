package fetch

import (
	"errors"
	"fmt"
	"math"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// ErrInvalidQuery identifies an invalid local range or account address.
// Such queries fail before any RPC request is sent.
var ErrInvalidQuery = errors.New("invalid RPC query")

// ErrQueryMismatch identifies a response whose count, heights, or account do
// not match the request. Hash consistency alone does not establish this binding.
var ErrQueryMismatch = errors.New("RPC response does not match query")

// MaxRangeQueryCount bounds one complete range, including any checkpoint row.
// It allows the default 100,000-header bundle plus its preceding checkpoint.
// This is a client transport guardrail, not a consensus limit.
const MaxRangeQueryCount = 100_001

func validateHeightRange(start, count uint64) error {
	if start == 0 || count == 0 || count > MaxRangeQueryCount || count-1 > math.MaxUint64-start {
		return fmt.Errorf("%w: start and count must be positive, count must not exceed %d, and the last height must fit uint64", ErrInvalidQuery, MaxRangeQueryCount)
	}
	return nil
}

func validateAccountQuery(address string, start, count uint64) (chain.Address, error) {
	if err := validateHeightRange(start, count); err != nil {
		return chain.Address{}, err
	}
	decoded, err := DecodeZenonAddress(address)
	if err != nil {
		return chain.Address{}, fmt.Errorf("%w: malformed account address", ErrInvalidQuery)
	}
	return chain.Address(decoded), nil
}
