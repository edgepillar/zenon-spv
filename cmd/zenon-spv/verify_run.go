package main

import (
	"fmt"
	"io"
	"os"

	"github.com/0x3639/zenon-spv/internal/verify"
)

func runVerifyHeaders(args []string) int {
	return runVerification("verify-headers", args, os.Stdout, os.Stderr)
}

func runVerifyCommitment(args []string) int {
	return runVerification("verify-commitment", args, os.Stdout, os.Stderr)
}

func runVerifySegment(args []string) int {
	return runVerification("verify-segment", args, os.Stdout, os.Stderr)
}

func runVerifyStateValue(args []string) int {
	return runVerification("verify-state-value", args, os.Stdout, os.Stderr)
}

func runVerification(command string, args []string, stdout, stderr io.Writer) int {
	out := newVerificationOutput(command, stdout, stderr)
	defer func() { _ = out.releaseStateLock() }() // Also release on panic, without emitting a success report.
	code := executeVerification(command, args, out)
	out.outcomeForExit(code) // Preserve known verification outcomes if lock release fails.
	if err := out.releaseStateLock(); err != nil {
		_, _ = fmt.Fprintf(out.diagnostics, "state lock: %v\n", err)
		out.stage, code = "state_lock", 70
	}
	return out.finish(code)
}

func executeVerification(command string, args []string, out *verificationOutput) int {
	ctx, code := prepareVerifierContext(command, args, out)
	if code != 0 {
		return code
	}
	out.stage = "verification"
	var state verify.VerifiedState
	var outcome verify.Outcome
	if command == "verify-headers" {
		result, extended := ctx.state.Extend(ctx.bundle.Headers)
		out.result("", reportReference{Scope: "headers"}, result)
		state, outcome = extended, result.Outcome
		if outcome == verify.OutcomeAccept {
			out.tip(state)
		}
	} else {
		state, code = ctx.stateForProof()
		if code != 0 {
			return code
		}
		outcome = ctx.verifyProofs(command, state)
	}
	out.outcome(outcome)
	if outcome == verify.OutcomeAccept {
		printAcceptCaveat(out.text, ctx.opts)
		out.report.Caveats = acceptanceCaveats(ctx.opts)
		out.stage = "persistence"
		if err := ctx.persist(state); err != nil {
			_, _ = fmt.Fprintf(out.diagnostics, "state: %v\n", err)
			return 70
		}
	}
	return outcomeExitCode(outcome)
}

func (ctx verifierContext) verifyProofs(command string, state verify.VerifiedState) verify.Outcome {
	out := ctx.output
	worst := verify.OutcomeAccept
	accumulate := func(o verify.Outcome) {
		if o == verify.OutcomeReject || (o == verify.OutcomeRefused && worst != verify.OutcomeReject) {
			worst = o
		}
	}
	missing := func(scope string) verify.Outcome {
		_, _ = fmt.Fprintf(out.text, "%s: REFUSED ReasonMissingEvidence (no %s in bundle)\n", scope, scope)
		out.record(reportReference{Scope: scope}, verify.Result{Outcome: verify.OutcomeRefused, Reason: verify.ReasonMissingEvidence, FailedAt: -1})
		return verify.OutcomeRefused
	}
	switch command {
	case "verify-commitment":
		if len(ctx.bundle.Commitments) == 0 {
			return missing("commitments")
		}
		for i, c := range ctx.bundle.Commitments {
			r := state.VerifyCommitment(c)
			out.result(fmt.Sprintf("commitment[%d] height=%d addr=%x", i, c.Height, c.Target.Address),
				reportReference{Scope: "commitment", Index: &i, MomentumHeight: &c.Height, AccountHeader: &c.Target}, r)
			accumulate(r.Outcome)
		}
	case "verify-segment":
		if len(ctx.bundle.Segments) == 0 {
			return missing("segments")
		}
		for si, seg := range ctx.bundle.Segments {
			result := state.VerifySegment(seg, ctx.bundle.Commitments)
			_, _ = fmt.Fprintf(out.text, "segment[%d] address=%x blocks=%d:\n", si, seg.Address, len(seg.Blocks))
			for bi, r := range result.Blocks {
				ref := reportReference{Scope: "segment", Index: &si}
				if r.FailedAt >= 0 && bi < len(seg.Blocks) {
					account := seg.Blocks[bi].AccountHeader()
					ref.BlockIndex, ref.AccountHeader = &bi, &account
				}
				out.result(segmentBlockLabel(bi, seg), ref, r)
			}
			accumulate(result.Worst())
		}
	case "verify-state-value":
		if len(ctx.bundle.StateValueProofs) == 0 {
			return missing("state_value_proofs")
		}
		for i, p := range ctx.bundle.StateValueProofs {
			r := state.VerifyStateValue(p)
			out.result(fmt.Sprintf("state_value_proof[%d] height=%d kind=%s", i, p.MomentumHeight, p.CommitmentKind),
				reportReference{Scope: "state_value_proof", Index: &i, MomentumHeight: &p.MomentumHeight}, r)
			accumulate(r.Outcome)
		}
	}
	return worst
}
