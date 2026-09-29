package main

import (
	"fmt"

	"github.com/0x3639/zenon-spv/internal/verify"
)

// stateForProof separates a normal header extension from an explicit query of
// an existing trusted local window. prepareVerifierContext performs the same
// bounded state validation and producer reauthorization before either path.
func (ctx verifierContext) stateForProof() (verify.VerifiedState, int) {
	out := ctx.output
	if ctx.retainedOnly {
		tip, ok := ctx.state.Tip()
		if !ok {
			_, _ = fmt.Fprintf(out.text, "state: REFUSED %s no retained headers\n", verify.ReasonMissingEvidence)
			out.record(reportReference{Scope: "state"}, verify.Result{Outcome: verify.OutcomeRefused, Reason: verify.ReasonMissingEvidence, FailedAt: -1})
			return ctx.state, 2
		}
		// This is provenance, not a new header-verification ACCEPT. Proof
		// results below remain responsible for their own bounded guarantees.
		_, _ = fmt.Fprintf(out.text, "retained_state: height=%d hash=%x\n", tip.Height, tip.HeaderHash)
		printTrustAssumptionsTo(out.text, "state_trust", ctx.state.TrustAssumptions())
		out.tip(ctx.state)
		return ctx.state, 0
	}
	result, state := ctx.state.Extend(ctx.bundle.Headers)
	out.result("headers", reportReference{Scope: "headers"}, result)
	if result.Outcome == verify.OutcomeAccept {
		out.tip(state)
	}
	return state, outcomeExitCode(result.Outcome)
}

func (ctx verifierContext) persist(state verify.VerifiedState) error {
	if ctx.retainedOnly || ctx.statePath == "" {
		return nil
	}
	if err := state.Save(ctx.statePath); err != nil {
		ctx.output.report.Persistence = "failed"
		return err
	}
	ctx.output.report.Persistence = "saved"
	return nil
}
