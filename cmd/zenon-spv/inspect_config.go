package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/0x3639/zenon-spv/internal/verify"
)

const inspectConfigUsage = "Usage: zenon-spv inspect-config [--genesis-config <path>] [--window {low|medium|high}] [--retain-headers <K>] [--protocol-profile <path>] [--schedule <path>] [--json]\n"

type configurationReport struct {
	SchemaVersion uint32                      `json:"schema_version"`
	Command       string                      `json:"command"`
	Status        string                      `json:"status"`
	ExitCode      int                         `json:"exit_code"`
	Error         *reportError                `json:"error"`
	Context       *verify.VerificationContext `json:"verification_context"`
	Trust         []verify.TrustAssumption    `json:"trust_assumptions"`
	Caveats       []string                    `json:"caveats"`
}

// Configuration inspection never loads retained state or candidate evidence.
// Success describes supported settings, not verified headers or provenance.
func runInspectConfig(args []string, stdout, stderr io.Writer) int {
	report := configurationReport{SchemaVersion: 1, Command: "inspect-config", Trust: []verify.TrustAssumption{},
		Caveats: []string{
			"Configuration inspection is not a proof result or an authentication of trust inputs.",
			"No state file, candidate evidence, producer coverage for a requested height, or RPC peer is checked.",
			"Fingerprint matching does not establish file provenance, network activation, canonicality, finality, or state values.",
		}}
	fs := flag.NewFlagSet("inspect-config", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	genesisPath := fs.String("genesis-config", "", "explicit genesis trust root")
	profilePath := fs.String("protocol-profile", "", "operator-attested activation profile")
	schedulePath := fs.String("schedule", "", "operator-attested producer schedule")
	tier := fs.String("window", "low", "policy window: low | medium | high")
	retainHeaders := fs.String("retain-headers", "", "explicit retained header capacity K (W < K <= 4096)")
	jsonOutput := fs.Bool("json", false, "emit a versioned configuration report")
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return writeConfigOutput(stdout, stderr, []byte(inspectConfigUsage), 0)
	} else if err != nil || fs.NArg() != 0 {
		report.Error = &reportError{Stage: "arguments", Category: "usage"}
		return finishConfiguration(report, 64, *jsonOutput, stdout, stderr)
	}
	policy, err := parseWindowPolicy(*tier)
	if err == nil {
		err = configureRetention(fs, *retainHeaders, &policy)
	}
	if err != nil {
		report.Error = &reportError{Stage: "arguments", Category: "usage"}
		return finishConfiguration(report, 64, *jsonOutput, stdout, stderr)
	}
	code := inspectConfiguration(&report, *genesisPath, *profilePath, *schedulePath, policy)
	return finishConfiguration(report, code, *jsonOutput, stdout, stderr)
}

func inspectConfiguration(report *configurationReport, genesisPath, profilePath, schedulePath string, policy verify.Policy) int {
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
	state, err := verify.NewVerifiedState(anchor, opts)
	if err != nil {
		return fail("configuration")
	}
	context, err := state.VerificationContext()
	if err != nil {
		return fail("context")
	}
	report.Context, report.Trust = &context, append(report.Trust, state.TrustAssumptions()...)
	return 0
}

func finishConfiguration(report configurationReport, code int, jsonOutput bool, stdout, stderr io.Writer) int {
	report.ExitCode, report.Status = code, "error"
	if code == 0 {
		report.Status = "configured"
	}
	if jsonOutput {
		raw, err := json.Marshal(report)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "inspect-config: cannot encode report")
			return 70
		}
		return writeConfigOutput(stdout, stderr, append(raw, '\n'), code)
	}
	var text bytes.Buffer
	if code != 0 {
		fmt.Fprintf(&text, "inspect-config: error at %s (%s)\n", report.Error.Stage, report.Error.Category)
		return writeConfigOutput(stderr, stderr, text.Bytes(), code)
	}
	raw, err := json.Marshal(report.Context)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "inspect-config: cannot encode context")
		return 70
	}
	fmt.Fprintf(&text, "verification_context: %s\n", raw)
	for _, caveat := range report.Caveats {
		fmt.Fprintln(&text, caveat)
	}
	return writeConfigOutput(stdout, stderr, text.Bytes(), 0)
}

func writeConfigOutput(destination, diagnostics io.Writer, raw []byte, code int) int {
	n, err := destination.Write(raw)
	if err != nil || n != len(raw) {
		_, _ = fmt.Fprintln(diagnostics, "inspect-config: cannot write report")
		return 70
	}
	return code
}
