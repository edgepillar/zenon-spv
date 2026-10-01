package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

const inspectStateUsage = "Usage: zenon-spv inspect-state --state <path> [--genesis-config <path>] [--window {low|medium|high}] [--retain-headers <K>] [--protocol-profile <path>] [--schedule <path>] [--expect-context <64-hex>] [--json]\n"

// Inspection deliberately has no ACCEPT outcome or proven guarantees. It
// describes a trusted local snapshot under explicitly selected settings.
type stateInspectionReport struct {
	SchemaVersion uint32                      `json:"schema_version"`
	Command       string                      `json:"command"`
	Status        string                      `json:"status"`
	ExitCode      int                         `json:"exit_code"`
	Reason        *string                     `json:"reason"`
	Error         *reportError                `json:"error"`
	Persistence   string                      `json:"persistence"`
	Context       *verify.VerificationContext `json:"verification_context"`
	Window        *verify.RetainedSummary     `json:"retained_window"`
	StateTrust    []verify.TrustAssumption    `json:"state_trust"`
	Caveats       []string                    `json:"caveats"`
}

func runInspectState(args []string, stdout, stderr io.Writer) int {
	report := stateInspectionReport{SchemaVersion: 1, Command: "inspect-state",
		Persistence: "read_only", StateTrust: []verify.TrustAssumption{},
		Caveats: []string{
			"Inspection describes a trusted local snapshot, not a proof result.",
			"No network freshness, canonicality, consensus finality, or state-value inclusion is established.",
			"File provenance and evicted ancestry remain external trust assumptions.",
		}}
	fs := flag.NewFlagSet("inspect-state", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	statePath := fs.String("state", "", "existing trusted state file")
	genesisPath := fs.String("genesis-config", "", "explicit genesis trust root")
	profilePath := fs.String("protocol-profile", "", "operator-attested activation profile")
	schedulePath := fs.String("schedule", "", "operator-attested producer schedule")
	tier := fs.String("window", "low", "policy window: low | medium | high")
	retainHeaders := fs.String("retain-headers", "", "explicit retained header capacity K (W < K <= 4096)")
	jsonOutput := fs.Bool("json", false, "emit a versioned inspection report")
	expectedContext := fs.String("expect-context", "", "require this 64-hex verification context fingerprint")
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return writeInspectionOutput(stdout, stderr, []byte(inspectStateUsage), 0)
	} else if err != nil || fs.NArg() != 0 || *statePath == "" {
		report.Error = &reportError{Stage: "arguments", Category: "usage"}
		return finishInspection(report, 64, *jsonOutput, stdout, stderr)
	}
	pin, err := parseContextPin(fs, *expectedContext)
	if err != nil {
		report.Error = &reportError{Stage: "arguments", Category: "usage"}
		return finishInspection(report, 64, *jsonOutput, stdout, stderr)
	}
	policy, err := parseWindowPolicy(*tier)
	if err == nil {
		err = configureRetention(fs, *retainHeaders, &policy)
	}
	if err != nil {
		report.Error = &reportError{Stage: "arguments", Category: "usage"}
		return finishInspection(report, 64, *jsonOutput, stdout, stderr)
	}
	code := inspectTrustedState(&report, *statePath, *genesisPath, *profilePath, *schedulePath, policy, pin)
	return finishInspection(report, code, *jsonOutput, stdout, stderr)
}

func inspectTrustedState(report *stateInspectionReport, statePath, genesisPath, profilePath, schedulePath string, policy verify.Policy, pin *chain.Hash) int {
	fail := func(stage string) int {
		report.Error = &reportError{Stage: stage, Category: "operational"}
		return 70
	}
	anchor, err := loadGenesis(genesisPath)
	if err != nil {
		return fail("genesis")
	}
	if err := configureProtocolProfile(&policy, profilePath, anchor); err != nil {
		return fail("protocol_profile")
	}
	opts := verify.VerifyOptions{Policy: policy}
	if schedulePath != "" {
		schedule, err := verify.LoadProducerSchedule(schedulePath)
		if err != nil || schedule.ChainID != anchor.ChainID {
			return fail("schedule")
		}
		opts.ProducerAuth = verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired,
			Authorizer: verify.NewScheduleAuthorizer(schedule)}
	}
	state, err := verify.LoadTrustedState(statePath, anchor, opts)
	if err != nil {
		var authorization *verify.StateAuthorizationError
		if errors.As(err, &authorization) {
			reason := authorization.Result.Reason.String()
			report.Reason = &reason
			return outcomeExitCode(authorization.Result.Outcome)
		}
		return fail("state")
	}
	if pin != nil {
		if err := state.RequireContextFingerprint(*pin); err != nil {
			return fail("context_pin")
		}
	}
	if state.Empty() {
		reason := verify.ReasonMissingEvidence.String()
		report.Reason = &reason
		return 2
	}
	context, err := state.VerificationContext()
	if err != nil {
		return fail("context")
	}
	window, err := state.RetainedSummary()
	if err != nil {
		return fail("state")
	}
	report.Context, report.Window = &context, &window
	report.StateTrust = append(report.StateTrust, state.TrustAssumptions()...)
	return 0
}

func finishInspection(report stateInspectionReport, code int, jsonOutput bool, stdout, stderr io.Writer) int {
	report.ExitCode = code
	switch code {
	case 0:
		report.Status = "inspected"
	case 1:
		report.Status = "rejected"
	case 2:
		report.Status = "refused"
	default:
		report.Status = "error"
	}
	if jsonOutput {
		raw, err := json.Marshal(report)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "inspect-state: cannot encode report")
			return 70
		}
		return writeInspectionOutput(stdout, stderr, append(raw, '\n'), code)
	}
	var text bytes.Buffer
	if code != 0 {
		fmt.Fprintf(&text, "inspect-state: %s", report.Status)
		if report.Reason != nil {
			fmt.Fprintf(&text, " %s", *report.Reason)
		}
		if report.Error != nil {
			fmt.Fprintf(&text, " at %s (%s)", report.Error.Stage, report.Error.Category)
		}
		fmt.Fprintln(&text)
		return writeInspectionOutput(stderr, stderr, text.Bytes(), code)
	}
	w := report.Window
	fmt.Fprintf(&text, "INSPECTED retained headers: %d/%d\noldest: %d %x\ntip: %d %x\n",
		w.Count, w.Capacity, w.Oldest.Height, w.Oldest.Hash, w.Tip.Height, w.Tip.Hash)
	if w.DepthEligible == nil {
		fmt.Fprintln(&text, "depth-eligible heights: none")
	} else {
		fmt.Fprintf(&text, "depth-eligible heights: %d..%d\n", w.DepthEligible.FromHeight, w.DepthEligible.ThroughHeight)
	}
	fmt.Fprintf(&text, "required depth: %d\nproducer authorization: %s\n", report.Context.Policy.W, report.Context.Producer.Mode)
	for _, caveat := range report.Caveats {
		fmt.Fprintln(&text, caveat)
	}
	return writeInspectionOutput(stdout, stderr, text.Bytes(), code)
}

func writeInspectionOutput(destination, diagnostics io.Writer, raw []byte, code int) int {
	n, err := destination.Write(raw)
	if err != nil || n != len(raw) {
		_, _ = fmt.Fprintln(diagnostics, "inspect-state: cannot write report")
		return 70
	}
	return code
}
