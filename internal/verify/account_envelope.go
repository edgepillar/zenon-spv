package verify

import (
	"errors"
	"fmt"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func validateSegmentEnvelope(b chain.AccountBlock, chainID uint64, index int) Result {
	if err := chain.ValidateAccountBlockEnvelope(b); err != nil {
		result := Result{Outcome: OutcomeReject, Reason: ReasonInvalidAccountBlockEnvelope, Message: err.Error(), FailedAt: index}
		switch {
		case errors.Is(err, chain.ErrUnsupportedAccountBlockVersion):
			result.Outcome, result.Reason = OutcomeRefused, ReasonUnsupportedAccountBlockVersion
		case errors.Is(err, chain.ErrUnsupportedAccountBlockType):
			result.Outcome, result.Reason = OutcomeRefused, ReasonUnsupportedAccountBlockType
		}
		return result
	}
	if b.ChainIdentifier != chainID {
		return Result{Outcome: OutcomeReject, Reason: ReasonChainIDMismatch, FailedAt: index,
			Message: fmt.Sprintf("account chain_id=%d != anchor chain_id=%d", b.ChainIdentifier, chainID)}
	}
	return accept()
}
