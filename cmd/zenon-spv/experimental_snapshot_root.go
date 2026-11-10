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
const experimentalSnapshotRootUsage = "Usage: zenon-spv inspect-experimental-snapshot-root --config <path> --expect-header-context <64-hex> --expect-height <height> --expect-header-hash <64-hex> [--projection-report <path> --expect-projection-sha256 <64-hex>] <momentums.json>\n"

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
	}) != nil || next.Version != 1 || boundExperimentalCLISchedule(schedule) != nil || json.Unmarshal(schedule, &next.Schedule) != nil {
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
	ProjectionComputationRechecked bool                              `json:"projection_computation_rechecked"`
	ReportProvenanceAuthenticated  bool                              `json:"report_provenance_authenticated"`
	ExcludedStateAuthenticated     bool                              `json:"excluded_state_authenticated"`
	ProductionStateValueGuarantee  bool                              `json:"production_state_value_guarantee"`
}

func runExperimentalSnapshotRoot(args []string, stdout, stderr io.Writer) int {
	report := experimentalSnapshotRootReport{SchemaVersion: 1, Command: experimentalSnapshotRootCommand, Scope: "EXPERIMENTAL_CONFIGURED_HEADER_ROOT"}
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
		return writeExperimentalBatch(stdout, stderr, append(raw, '\n'), code)
	}
	fs := flag.NewFlagSet(experimentalSnapshotRootCommand, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "independently selected experimental header configuration")
	heightText := fs.String("expect-height", "", "independently selected header height")
	projectionPath := fs.String("projection-report", "", "selected completed S1 projection report")
	contextPin, headerPin, projectionPin := new(contextPinFlag), new(contextPinFlag), new(contextPinFlag)
	fs.Var(contextPin, "expect-header-context", "independently selected experimental header context fingerprint")
	fs.Var(headerPin, "expect-header-hash", "independently selected header hash")
	fs.Var(projectionPin, "expect-projection-sha256", "independently selected projection report SHA-256")
	selections := registerSelectionGuards(fs)
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return writeExperimentalBatch(stdout, stderr, []byte(experimentalSnapshotRootUsage), 0)
	} else if err != nil || selections() != nil || fs.NArg() != 1 || *configPath == "" {
		return finish(64, "arguments", "usage")
	}
	height, heightErr := strconv.ParseUint(*heightText, 10, 64)
	expectedContext, contextErr := parseContextPin(contextPin)
	expectedHeader, headerErr := parseContextPin(headerPin)
	expectedProjection, projectionErr := parseContextPin(projectionPin)
	projectionPathSupplied := false
	fs.Visit(func(f *flag.Flag) { projectionPathSupplied = projectionPathSupplied || f.Name == "projection-report" })
	if heightErr != nil || height == 0 || strconv.FormatUint(height, 10) != *heightText ||
		contextErr != nil || expectedContext == nil || expectedContext.IsZero() ||
		headerErr != nil || expectedHeader == nil || expectedHeader.IsZero() ||
		projectionErr != nil || projectionPathSupplied != projectionPin.supplied ||
		projectionPathSupplied && (*projectionPath == "" || expectedProjection == nil || expectedProjection.IsZero()) {
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
	raw, err = readExperimentalCLIFile(fs.Arg(0), maxExperimentalBundleBytes, openExperimentalCLIFile)
	if err != nil {
		return finish(70, "headers", "invalid_input")
	}
	headers, err := decodeExperimentalCLIHeaders(raw, config.Policy.MaxBatchHeaders)
	if err != nil {
		return finish(70, "headers", "invalid_encoding")
	}
	result, accepted := state.Extend(headers)
	report.HeaderChecks = &experimentalCLIHeaderReport{result.Outcome.String(), result.Reason.String(), result.FailedAt}
	if result.Outcome != verify.OutcomeAccept {
		return finish(outcomeExitCode(result.Outcome), "headers", "not_accepted")
	}
	root, err := accepted.RootAt(height, *expectedHeader, *expectedContext)
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
	context, err := accepted.Context()
	if err != nil {
		return finish(70, "selection", "invalid_state")
	}
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
		report.Projection = &projection.Comparison
	}
	tip := headers[len(headers)-1].Header
	report.Context = &context
	report.Header = &experimentalSnapshotHeader{height, *expectedHeader, root, tip.Height, tip.HeaderHash}
	return finish(0, "", "")
}
