package chain

import (
	"errors"
	"math/big"
)

// MaxAccountAmountBits follows the pinned node's send-amount bound. Receive
// amounts are zero there; this common scalar check is not full block validation.
const MaxAccountAmountBits = 255

var ErrInvalidAccountAmount = errors.New("account amount must be non-negative and at most 255 bits")

// ValidateAccountAmount prevents signed-value aliases at both the RPC and
// offline proof boundaries. Nil retains the low-level zero representation.
func ValidateAccountAmount(amount *big.Int) error {
	if amount != nil && (amount.Sign() < 0 || amount.BitLen() > MaxAccountAmountBits) {
		return ErrInvalidAccountAmount
	}
	return nil
}
