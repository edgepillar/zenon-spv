package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/statelock"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// verificationReport is a local diagnostic, not a signed proof receipt. Keep
// command failure and persistence separate from the cryptographic outcome.
// Never add paths, arbitrary error messages, or private provenance metadata.
type verificationReport struct {
	SchemaVersion   uint32                      `json:"schema_version"`
	Command         string                      `json:"command"`
	Mode            string                      `json:"mode"`
	ExitCode        int                         `json:"exit_code"`
	Outcome         *string                     `json:"outcome"`
	Error           *reportError                `json:"error"`
	Persistence     string                      `json:"persistence"`
	Context         *verify.VerificationContext `json:"verification_context"`
	VerificationTip *chain.HashHeight           `json:"verification_tip"`
	StateTrust      []verify.TrustAssumption    `json:"state_trust"`
	Results         []reportResult              `json:"results"`
	Caveats         []string                    `json:"caveats"`
}

type reportError struct {
	Stage    string `json:"stage"`
	Category string `json:"category"`
}

// References identify input entries, including rejected claims. They do not
// authenticate a target by themselves. A synthetic segment-level refusal has
// no block_index or account_header, even when that segment contains blocks.
type reportReference struct {
	Scope          string               `json:"scope"`
	Index          *int                 `json:"index,omitempty"`
	BlockIndex     *int                 `json:"block_index,omitempty"`
	MomentumHeight *uint64              `json:"momentum_height,omitempty"`
	AccountHeader  *chain.AccountHeader `json:"account_header,omitempty"`
}

type reportResult struct {
	Reference        reportReference          `json:"reference"`
	Outcome          string                   `json:"outcome"`
	Reason           string                   `json:"reason"`
	FailedAt         int                      `json:"failed_at"`
	Proven           []verify.Guarantee       `json:"proven"`
	NotProven        []verify.Guarantee       `json:"not_proven"`
	TrustAssumptions []verify.TrustAssumption `json:"trust_assumptions"`
}

type verificationOutput struct {
	json        bool
	text        io.Writer
	diagnostics io.Writer
	destination io.Writer
	errOutput   io.Writer
	stage       string
	stateLock   *statelock.Lock
	report      verificationReport
}

func (o *verificationOutput) releaseStateLock() error {
	lock := o.stateLock
	o.stateLock = nil
	return lock.Close()
}

func newVerificationOutput(command string, stdout, stderr io.Writer) *verificationOutput {
	return &verificationOutput{
		text: stdout, diagnostics: stderr, destination: stdout, errOutput: stderr, stage: "arguments",
		report: verificationReport{SchemaVersion: 1, Command: command, Mode: "extend",
			Persistence: "not_requested", StateTrust: []verify.TrustAssumption{},
			Results: []reportResult{}, Caveats: []string{}},
	}
}

func (o *verificationOutput) configure(jsonOutput, retainedOnly bool, statePath string) {
	o.json = jsonOutput
	if jsonOutput {
		o.text, o.diagnostics = io.Discard, io.Discard
	}
	if statePath != "" {
		o.report.Persistence = "not_attempted"
	}
	if retainedOnly {
		o.report.Mode, o.report.Persistence = "retained_only", "read_only"
	}
}

func (o *verificationOutput) record(ref reportReference, r verify.Result) {
	if !o.json {
		return
	}
	o.report.Results = append(o.report.Results, reportResult{
		Reference: ref, Outcome: r.Outcome.String(), Reason: r.Reason.String(), FailedAt: r.FailedAt,
		Proven: append([]verify.Guarantee{}, r.Proven...), NotProven: append([]verify.Guarantee{}, r.NotProven...),
		TrustAssumptions: append([]verify.TrustAssumption{}, r.TrustAssumptions...),
	})
}

func (o *verificationOutput) result(label string, ref reportReference, r verify.Result) {
	printResultTo(o.text, label, r)
	o.record(ref, r)
}

func (o *verificationOutput) tip(state verify.VerifiedState) {
	if h, ok := state.Tip(); ok {
		o.report.VerificationTip = &chain.HashHeight{Hash: h.HeaderHash, Height: h.Height}
	}
	o.report.StateTrust = append([]verify.TrustAssumption{}, state.TrustAssumptions()...)
}

func (o *verificationOutput) outcome(outcome verify.Outcome) {
	token := outcome.String()
	o.report.Outcome = &token
}

func (o *verificationOutput) outcomeForExit(code int) {
	switch code {
	case 0:
		o.outcome(verify.OutcomeAccept)
	case 1:
		o.outcome(verify.OutcomeReject)
	case 2:
		o.outcome(verify.OutcomeRefused)
	}
}

// finish emits one JSON value only after verification and any save attempt.
// A failed write cannot reliably describe itself on stdout; the process exit
// code is authoritative. Saving is not rolled back when report output fails.
func (o *verificationOutput) finish(code int) int {
	if !o.json {
		return code
	}
	o.outcomeForExit(code)
	if code != 0 && code != 1 && code != 2 {
		category := "operational"
		if code == 64 {
			category = "usage"
		}
		o.report.Error = &reportError{Stage: o.stage, Category: category}
	}
	o.report.ExitCode = code
	raw, err := json.Marshal(o.report)
	if err == nil {
		raw = append(raw, '\n')
		var n int
		n, err = o.destination.Write(raw)
		if err == nil && n != len(raw) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(o.errOutput, "report: cannot write JSON output")
		return 70
	}
	return code
}
