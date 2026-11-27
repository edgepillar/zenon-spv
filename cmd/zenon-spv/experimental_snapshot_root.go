// SPDX-License-Identifier: MIT

package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strconv"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

const experimentalSnapshotRootCommand = "inspect-experimental-snapshot-root"
const experimentalSnapshotExportCommand = "export-experimental-snapshot-header-state"
const experimentalSnapshotOptions = " --config <path> --expect-header-context <64-hex> --expect-height <height> --expect-header-hash <64-hex> [--trusted-state <path> --expect-state-sha256 <64-hex>] [--projection-report <path> --expect-projection-sha256 <64-hex>] [<momentums.json>]\n"

type experimentalSnapshotConfig struct {
	Version  uint32
	Profile  verify.ExperimentalV3Profile
	Policy   verify.ExperimentalV3Policy
	Schedule *verify.ProducerSchedule
}

func decodeExperimentalSnapshotConfig(raw []byte) (experimentalSnapshotConfig, error) {
	var next experimentalSnapshotConfig
	var schedule json.RawMessage
	if len(raw) > maxExperimentalConfigBytes || decodeExperimentalCLIObject(raw, map[string]any{
		"version": &next.Version, "header_profile": &next.Profile,
		"header_policy": &next.Policy, "producer_schedule": &schedule,
	}) != nil || next.Version != 1 {
		return experimentalSnapshotConfig{}, errExperimentalCLIInput
	}
	var err error
	next.Schedule, err = verify.DecodeExperimentalV3Schedule(schedule)
	if err != nil {
		return experimentalSnapshotConfig{}, errExperimentalCLIInput
	}
	return next, nil
}

type experimentalSnapshotHeader struct {
	Height    uint64     `json:"height"`
	Hash      chain.Hash `json:"hash"`
	StateRoot chain.Hash `json:"state_root"`
	TipHeight uint64     `json:"tip_height"`
	TipHash   chain.Hash `json:"tip_hash"`
}

type experimentalSnapshotRootReport struct {
	SchemaVersion                  uint32                            `json:"schema_version"`
	Command                        string                            `json:"command"`
	Scope                          string                            `json:"scope"`
	Status                         string                            `json:"status"`
	ExitCode                       int                               `json:"exit_code"`
	Error                          *reportError                      `json:"error"`
	Context                        *verify.ExperimentalV3Context     `json:"header_context"`
	HeaderChecks                   *experimentalCLIHeaderReport      `json:"header_checks"`
	Header                         *experimentalSnapshotHeader       `json:"header"`
	Projection                     *experimentalProjectionComparison `json:"projection_comparison"`
	StateInput                     *experimentalCLIStateInputReport  `json:"state_input,omitempty"`
	StateOutput                    *experimentalCLIStateOutput       `json:"state_output,omitempty"`
	ProjectionComputationRechecked bool                              `json:"projection_computation_rechecked"`
	ReportProvenanceAuthenticated  bool                              `json:"report_provenance_authenticated"`
	ExcludedStateAuthenticated     bool                              `json:"excluded_state_authenticated"`
	ProductionStateValueGuarantee  bool                              `json:"production_state_value_guarantee"`
}

func runExperimentalSnapshotRoot(command string, args []string, stdout, stderr io.Writer) int {
	export := command == experimentalSnapshotExportCommand
	report := experimentalSnapshotRootReport{SchemaVersion: 1, Command: command, Scope: "EXPERIMENTAL_CONFIGURED_HEADER_ROOT"}
	reportOutput := stdout
	if export {
		reportOutput = stderr
	}
	finish := func(code int, stage, category string) int {
		report.ExitCode = code
		switch code {
		case 0:
			report.Status = "selected"
			if report.Projection != nil {
				report.Status = "matched"
			}
		case 1:
			report.Status = "rejected"
		case 2:
			report.Status = "refused"
		default:
			report.Status = "error"
		}
		if code != 0 {
			report.Error = &reportError{Stage: stage, Category: category}
		}
		raw, err := json.Marshal(report)
		if err != nil {
			return 70
		}
		return writeExperimentalBatch(reportOutput, stderr, append(raw, '\n'), code)
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "independently selected experimental header configuration")
	heightText := fs.String("expect-height", "", "independently selected header height")
	projectionPath := fs.String("projection-report", "", "selected completed or replayed S1 projection report")
	checkpointPath := fs.String("trusted-state", "", "explicit trusted local experimental header checkpoint")
	contextPin, headerPin, projectionPin, checkpointPin := new(contextPinFlag), new(contextPinFlag), new(contextPinFlag), new(contextPinFlag)
	fs.Var(contextPin, "expect-header-context", "independently selected experimental header context fingerprint")
	fs.Var(headerPin, "expect-header-hash", "independently selected header hash")
	fs.Var(projectionPin, "expect-projection-sha256", "independently selected projection report SHA-256")
	fs.Var(checkpointPin, "expect-state-sha256", "independently selected trusted checkpoint SHA-256")
	selections := registerSelectionGuards(fs)
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		usage := "Usage: zenon-spv " + command + experimentalSnapshotOptions
		return writeExperimentalBatch(stdout, stderr, []byte(usage), 0)
	} else if err != nil || selections() != nil || fs.NArg() > 1 || *configPath == "" {
		return finish(64, "arguments", "usage")
	}
	height, heightErr := strconv.ParseUint(*heightText, 10, 64)
	expectedContext, contextErr := parseContextPin(contextPin)
	expectedHeader, headerErr := parseContextPin(headerPin)
	expectedProjection, projectionErr := parseExperimentalCLIFilePin(fs, "projection-report", *projectionPath, projectionPin)
	expectedCheckpoint, checkpointErr := parseExperimentalCLIFilePin(fs, "trusted-state", *checkpointPath, checkpointPin)
	if heightErr != nil || height == 0 || strconv.FormatUint(height, 10) != *heightText ||
		contextErr != nil || expectedContext == nil || expectedContext.IsZero() ||
		headerErr != nil || expectedHeader == nil || expectedHeader.IsZero() ||
		projectionErr != nil || checkpointErr != nil || expectedCheckpoint == nil && fs.NArg() == 0 {
		return finish(64, "arguments", "usage")
	}
	raw, err := readExperimentalCLIFile(*configPath, maxExperimentalConfigBytes, openExperimentalCLIFile)
	if err != nil {
		return finish(70, "configuration", "invalid_input")
	}
	config, err := decodeExperimentalSnapshotConfig(raw)
	if err != nil {
		return finish(70, "configuration", "invalid_configuration")
	}
	state, err := verify.NewExperimentalV3State(config.Profile, config.Policy, config.Schedule, *expectedContext)
	if errors.Is(err, verify.ErrContextFingerprintMismatch) {
		return finish(70, "configuration_pin", "mismatch")
	}
	if err != nil {
		return finish(70, "configuration", "invalid_configuration")
	}
	if expectedCheckpoint != nil {
		resumed, input, code, category := readExperimentalCLIState(state, *checkpointPath, *expectedCheckpoint)
		if code != 0 {
			return finish(code, "state_input", category)
		}
		state, report.StateInput = resumed, input
	}
	var headers []chain.CandidateV3Header
	if fs.NArg() > 0 {
		raw, err = readExperimentalCLIFile(fs.Arg(0), maxExperimentalBundleBytes, openExperimentalCLIFile)
		if err != nil {
			return finish(70, "headers", "invalid_input")
		}
		headers, err = decodeExperimentalCLIHeaders(raw, config.Policy.MaxBatchHeaders)
		if err != nil {
			return finish(70, "headers", "invalid_encoding")
		}
	}
	if report.StateInput != nil {
		report.StateInput.ProviderHeaders = uint32(len(headers))
	}
	if len(headers) > 0 || expectedCheckpoint == nil {
		result, next := state.Extend(headers)
		report.HeaderChecks = &experimentalCLIHeaderReport{result.Outcome.String(), result.Reason.String(), result.FailedAt}
		if result.Outcome != verify.OutcomeAccept {
			return finish(outcomeExitCode(result.Outcome), "headers", "not_accepted")
		}
		state = next
	}
	root, err := state.RootAt(height, *expectedHeader, *expectedContext)
	switch {
	case errors.Is(err, verify.ErrExperimentalV3HeaderMismatch):
		return finish(1, "selection", "header_hash_mismatch")
	case errors.Is(err, verify.ErrExperimentalV3HeaderUnavailable):
		return finish(2, "selection", "header_unavailable")
	case errors.Is(err, verify.ErrExperimentalV3Depth):
		return finish(2, "selection", "insufficient_depth")
	case err != nil:
		return finish(70, "selection", "invalid_state")
	}
	context, err := state.Context()
	if err != nil {
		return finish(70, "selection", "invalid_state")
	}
	tip, ok := state.Tip()
	if !ok {
		return finish(70, "selection", "invalid_state")
	}
	var comparison *experimentalProjectionComparison
	if expectedProjection != nil {
		raw, err := readExperimentalCLIFile(*projectionPath, maxSnapshotProjectionReportBytes, openExperimentalCLIFile)
		if err != nil {
			return finish(70, "projection", "invalid_input")
		}
		if sha256.Sum256(raw) != [sha256.Size]byte(*expectedProjection) {
			return finish(1, "projection", "digest_mismatch")
		}
		projection, err := decodeSnapshotProjectionReport(raw)
		if err != nil {
			return finish(70, "projection", "invalid_report")
		}
		if projection.Height != height || projection.Hash != *expectedHeader {
			return finish(1, "projection", "frontier_mismatch")
		}
		if projection.Root != root {
			return finish(1, "projection", "root_mismatch")
		}
		projection.Comparison.ReportSHA256 = *expectedProjection
		comparison = &projection.Comparison
	}
	if export {
		written, err := exportExperimentalCLIState(state, stdout)
		if err != nil {
			return finish(70, "checkpoint_output", "write_failed")
		}
		report.StateOutput = written
	}
	report.Context = &context
	report.Header = &experimentalSnapshotHeader{height, *expectedHeader, root, tip.Height, tip.Hash}
	report.Projection = comparison
	return finish(0, "", "")
}
