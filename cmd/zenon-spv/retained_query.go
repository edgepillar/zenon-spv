package main

import (
	"fmt"
	"os"

	"github.com/0x3639/zenon-spv/internal/verify"
)

// stateForProof separates a normal header extension from an explicit query of
// an existing trusted local window. prepareVerifierContext performs the same
// bounded state validation and producer reauthorization before either path.
func (ctx verifierContext) stateForProof() (verify.VerifiedState, int) {
	if ctx.retainedOnly {
		tip, ok := ctx.state.Tip()
		if !ok {
			fmt.Printf("state: REFUSED %s no retained headers\n", verify.ReasonMissingEvidence)
			return ctx.state, 2
		}
		// This is provenance, not a new header-verification ACCEPT. Proof
		// results below remain responsible for their own bounded guarantees.
		fmt.Printf("retained_state: height=%d hash=%x\n", tip.Height, tip.HeaderHash)
		printTrustAssumptionsTo(os.Stdout, "state_trust", ctx.state.TrustAssumptions())
		return ctx.state, 0
	}
	result, state := ctx.state.Extend(ctx.bundle.Headers)
	printResult("headers", result)
	return state, outcomeExitCode(result.Outcome)
}

func (ctx verifierContext) persist(state verify.VerifiedState) error {
	if ctx.retainedOnly || ctx.statePath == "" {
		return nil
	}
	return state.Save(ctx.statePath)
}
