// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

const experimentalContextConfigCommand = "inspect-experimental-batch-context-config"
const experimentalContextQueryCommand = "query-experimental-batch-context"
const experimentalContextConfigUsage = "Usage: zenon-spv inspect-experimental-batch-context-config --config <path>\n"
const experimentalContextQueryUsage = "Usage: zenon-spv query-experimental-batch-context --config <path> --request <path> --expect-header-context <64-hex> --expect-query-context <64-hex> [--compare-gateway] <bundle.json>\n"

type experimentalContextCLIReport struct {
	SchemaVersion                 uint32                                          `json:"schema_version"`
	Command                       string                                          `json:"command"`
	Scope                         string                                          `json:"scope"`
	Status                        string                                          `json:"status"`
	ExitCode                      int                                             `json:"exit_code"`
	Error                         *reportError                                    `json:"error"`
	HeaderContext                 *verify.ExperimentalV3Context                   `json:"header_context"`
	QueryContext                  *verify.ExperimentalBatchContext                `json:"query_context"`
	Headers                       *experimentalCLIHeaderReport                    `json:"headers"`
	Result                        *verify.ExperimentalBatchContextResult          `json:"result"`
	Gateway                       *verify.ExperimentalBatchEntryGatewayComparison `json:"gateway_comparison"`
	Persistence                   string                                          `json:"persistence"`
	RPCRequests                   uint32                                          `json:"rpc_requests"`
	ProductionStateValueGuarantee bool                                            `json:"production_state_value_guarantee"`
	GatewayComparisonRequested    bool                                            `json:"gateway_comparison_requested"`
	Caveats                       []string                                        `json:"caveats"`
}

// Diagnostics and queries share bounded configuration parsing, but inspection
// never loads a provider bundle, authenticates headers or returns a typed row.
func runExperimentalBatchContext(command string, args []string, stdout, stderr io.Writer) int {
	inspect := command == experimentalContextConfigCommand
	report := experimentalContextCLIReport{SchemaVersion: 1, Command: command, Persistence: "read_only", Scope: "EXPERIMENTAL_CONFIGURED_HEADER_THREE_ROW_MEMBERSHIP", Caveats: []string{
		"Configured fingerprints do not authenticate network activation, file provenance or independently selected trust inputs.",
		"Configured-header membership does not establish canonicality, consensus finality, STF correctness, funds release or recipient receive.",
		"No witness availability, freshness or production state-value guarantee is established.",
		"Current-H domain/config does not establish submission-time context or STF execution.",
		"Gateway stored-field comparison is separate; a mismatch does not invalidate the historical membership result.",
	}}
	if inspect {
		report.Scope = "EXPERIMENTAL_CONFIGURATION_DIAGNOSTIC"
	}
	finish := func(code int, stage, category string) int {
		if stage != "" {
			report.Error = &reportError{Stage: stage, Category: category}
		}
		return finishExperimentalBatchContext(report, code, stdout, stderr)
	}
	if !inspect && command != experimentalContextQueryCommand {
		return finish(64, "arguments", "usage")
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "independently selected experimental configuration")
	var requestPath *string
	var compare *bool
	headerPin, queryPin := new(contextPinFlag), new(contextPinFlag)
	if !inspect {
		requestPath = fs.String("request", "", "separate locally selected query identity")
		compare = fs.Bool("compare-gateway", false, "compare the frontier DTO separately from historical proof validity")
		fs.Var(headerPin, "expect-header-context", "required independently selected header context fingerprint")
		fs.Var(queryPin, "expect-query-context", "required independently selected typed-query context fingerprint")
	}
	selections := registerSelectionGuards(fs)
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		usage := experimentalContextQueryUsage
		if inspect {
			usage = experimentalContextConfigUsage
		}
		return writeExperimentalBatch(stdout, stderr, []byte(usage), 0)
	} else if err != nil || selections() != nil || *configPath == "" || inspect && fs.NArg() != 0 || !inspect && (fs.NArg() != 1 || *requestPath == "") {
		return finish(64, "arguments", "usage")
	}
	var selectedHeader, selectedQuery *chain.Hash
	if !inspect {
		var err error
		if selectedHeader, err = parseContextPin(headerPin); err != nil || selectedHeader == nil || selectedHeader.IsZero() {
			return finish(64, "arguments", "usage")
		}
		if selectedQuery, err = parseContextPin(queryPin); err != nil || selectedQuery == nil || selectedQuery.IsZero() {
			return finish(64, "arguments", "usage")
		}
		report.GatewayComparisonRequested = *compare
	}
	raw, err := readExperimentalCLIFile(*configPath, maxExperimentalConfigBytes, openExperimentalCLIFile)
	if err != nil {
		return finish(70, "configuration", "invalid_input")
	}
	config, err := decodeExperimentalContextCLIConfig(raw)
	if err != nil {
		return finish(70, "configuration", "invalid_configuration")
	}
	headerContext, err := verify.ExperimentalV3ContextFor(config.HeaderProfile, config.HeaderPolicy, config.Schedule)
	if err != nil {
		return finish(70, "configuration", "unsupported_configuration")
	}
	// Inspection can construct only an empty handle to obtain the typed
	// diagnostic. It never extends headers or constructs a query handle.
	empty, err := verify.NewExperimentalV3State(config.HeaderProfile, config.HeaderPolicy, config.Schedule, headerContext.Fingerprint)
	if err != nil {
		return finish(70, "configuration", "invalid_configuration")
	}
	queryContext, err := verify.ExperimentalBatchContextFor(empty, config.QueryProfile)
	if err != nil {
		return finish(70, "configuration", "unsupported_configuration")
	}
	if inspect {
		report.HeaderContext, report.QueryContext = &headerContext, &queryContext
		return finish(0, "", "")
	}
	if *selectedHeader != headerContext.Fingerprint || *selectedQuery != queryContext.Fingerprint {
		return finish(70, "configuration_pin", "mismatch")
	}
	raw, err = readExperimentalCLIFile(*requestPath, maxExperimentalRequestBytes, openExperimentalCLIFile)
	if err != nil {
		return finish(70, "request", "invalid_input")
	}
	request, err := verify.DecodeExperimentalBatchContextRequest(raw)
	if err != nil || request.Context != *selectedQuery {
		return finish(70, "request", "invalid_identity")
	}
	raw, err = readExperimentalCLIFile(fs.Arg(0), maxExperimentalBundleBytes, openExperimentalCLIFile)
	if err != nil {
		return finish(70, "bundle", "invalid_input")
	}
	bundle, err := decodeExperimentalContextCLIBundle(raw, config.HeaderPolicy.MaxBatchHeaders, *compare)
	if errors.Is(err, fetch.ErrCandidateStateUnavailable) {
		return finish(2, "witness", "unavailable")
	}
	if errors.Is(err, errExperimentalCLIGatewayUnavailable) {
		return finish(2, "gateway", "unavailable")
	}
	if err != nil {
		return finish(70, "bundle", "invalid_encoding")
	}
	headerResult, state := empty.Extend(bundle.Headers)
	report.Headers = &experimentalCLIHeaderReport{headerResult.Outcome.String(), headerResult.Reason.String(), headerResult.FailedAt}
	if headerResult.Outcome != verify.OutcomeAccept {
		return finish(outcomeExitCode(headerResult.Outcome), "headers", "not_accepted")
	}
	query, err := verify.NewExperimentalBatchContextQuery(state, config.QueryProfile, *selectedQuery)
	if err != nil {
		return finish(70, "query", "invalid_configuration")
	}
	result, err := query.QueryWitnesses(request, bundle.Witnesses)
	if err != nil {
		code, category := experimentalBatchContextQueryError(err)
		return finish(code, "query", category)
	}
	if *compare {
		comparison := result.CompareGateway(*bundle.Gateway)
		report.Gateway = &comparison
	}
	report.HeaderContext, report.QueryContext, report.Result = &headerContext, &queryContext, &result
	return finish(0, "", "")
}

func experimentalBatchContextQueryError(err error) (int, string) {
	switch {
	case errors.Is(err, verify.ErrExperimentalBatchEntryAbsent):
		return 2, "typed_value_absent"
	case errors.Is(err, proof.ErrCandidateSMTBounds), errors.Is(err, proof.ErrCandidateBatchEntryBounds), errors.Is(err, proof.ErrCandidateDomainBounds):
		return 2, "unsupported_bounds"
	case errors.Is(err, verify.ErrExperimentalV3HeaderUnavailable), errors.Is(err, verify.ErrExperimentalV3Depth):
		return 2, "outside_owned_scope"
	case errors.Is(err, verify.ErrExperimentalBatchContextPin), errors.Is(err, verify.ErrExperimentalBatchEntryContext), errors.Is(err, verify.ErrExperimentalBatchEntryTip), errors.Is(err, verify.ErrExperimentalV3HeaderMismatch):
		return 1, "query_identity_mismatch"
	case errors.Is(err, verify.ErrExperimentalBatchEntryGateway):
		return 1, "gateway_mismatch"
	case errors.Is(err, verify.ErrExperimentalBatchEntryWitnessRoot), errors.Is(err, verify.ErrExperimentalBatchEntryWitnessValue), errors.Is(err, verify.ErrExperimentalBatchEntryCanonical), errors.Is(err, proof.ErrCandidateSMTEncoding), errors.Is(err, proof.ErrCandidateSMTPath), errors.Is(err, proof.ErrCandidateSMTMismatch), errors.Is(err, proof.ErrCandidateBatchEntryEncoding), errors.Is(err, proof.ErrCandidateDomainEncoding), errors.Is(err, verify.ErrExperimentalDomainRecordRule):
		return 1, "invalid_witness"
	default:
		return 70, "operational"
	}
}

func finishExperimentalBatchContext(report experimentalContextCLIReport, code int, stdout, stderr io.Writer) int {
	report.ExitCode = code
	switch code {
	case 0:
		report.Status = "matched"
		if report.Command == experimentalContextConfigCommand {
			report.Status = "inspected"
		}
	case 1:
		report.Status = "rejected"
	case 2:
		report.Status = "refused"
	default:
		report.Status = "error"
	}
	if code != 0 {
		report.Result = nil
	}
	raw, err := json.Marshal(report)
	if err != nil {
		// In particular, opaque non-UTF-8 ABI strings must not be silently
		// replaced in JSON. Emit only an error envelope and no partial row.
		report.Result, report.Error, report.Status, report.ExitCode = nil, &reportError{Stage: "output", Category: "encoding"}, "error", 70
		code = 70
		raw, err = json.Marshal(report)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "experimental query: cannot encode report")
			return 70
		}
	}
	return writeExperimentalBatch(stdout, stderr, append(raw, '\n'), code)
}
