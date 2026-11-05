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

const experimentalConfigCommand = "inspect-experimental-batch-config"
const experimentalQueryCommand = "query-experimental-batch-entry"
const experimentalConfigUsage = "Usage: zenon-spv inspect-experimental-batch-config --config <path>\n"
const experimentalQueryUsage = "Usage: zenon-spv query-experimental-batch-entry --config <path> --request <path> --expect-header-context <64-hex> --expect-query-context <64-hex> [--compare-gateway] <bundle.json>\n"

type experimentalCLIHeaderReport struct {
	Outcome  string `json:"outcome"`
	Reason   string `json:"reason"`
	FailedAt int    `json:"failed_at"`
}

type experimentalCLIReport struct {
	SchemaVersion                 uint32                                `json:"schema_version"`
	Command                       string                                `json:"command"`
	Scope                         string                                `json:"scope"`
	Status                        string                                `json:"status"`
	ExitCode                      int                                   `json:"exit_code"`
	Error                         *reportError                          `json:"error"`
	HeaderContext                 *verify.ExperimentalV3Context         `json:"header_context"`
	QueryContext                  *verify.ExperimentalBatchEntryContext `json:"query_context"`
	Headers                       *experimentalCLIHeaderReport          `json:"headers"`
	Result                        *verify.ExperimentalBatchEntryResult  `json:"result"`
	Persistence                   string                                `json:"persistence"`
	RPCRequests                   uint32                                `json:"rpc_requests"`
	ProductionStateValueGuarantee bool                                  `json:"production_state_value_guarantee"`
	GatewayComparisonRequired     bool                                  `json:"gateway_comparison_required"`
	Caveats                       []string                              `json:"caveats"`
}

// Diagnostics and queries share bounded configuration parsing, but inspection
// never loads a provider bundle, authenticates headers or returns a typed row.
func runExperimentalBatch(command string, args []string, stdout, stderr io.Writer) int {
	inspect := command == experimentalConfigCommand
	report := experimentalCLIReport{SchemaVersion: 1, Command: command, Persistence: "read_only", Scope: "EXPERIMENTAL_CONFIGURED_HEADER_MEMBERSHIP", Caveats: []string{
		"Configured fingerprints do not authenticate network activation, file provenance or independently selected trust inputs.",
		"Configured-header membership does not establish canonicality, consensus finality, STF correctness, funds release or recipient receive.",
		"No witness availability, freshness or production state-value guarantee is established.",
	}}
	if inspect {
		report.Scope = "EXPERIMENTAL_CONFIGURATION_DIAGNOSTIC"
	}
	finish := func(code int, stage, category string) int {
		if stage != "" {
			report.Error = &reportError{Stage: stage, Category: category}
		}
		return finishExperimentalBatch(report, code, stdout, stderr)
	}
	if !inspect && command != experimentalQueryCommand {
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
		compare = fs.Bool("compare-gateway", false, "require and compare all selected gateway stored fields")
		fs.Var(headerPin, "expect-header-context", "required independently selected header context fingerprint")
		fs.Var(queryPin, "expect-query-context", "required independently selected typed-query context fingerprint")
	}
	selections := registerSelectionGuards(fs)
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		usage := experimentalQueryUsage
		if inspect {
			usage = experimentalConfigUsage
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
		report.GatewayComparisonRequired = *compare
	}
	raw, err := readExperimentalCLIFile(*configPath, maxExperimentalConfigBytes, openExperimentalCLIFile)
	if err != nil {
		return finish(70, "configuration", "invalid_input")
	}
	config, err := decodeExperimentalCLIConfig(raw)
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
	queryContext, err := verify.ExperimentalBatchEntryContextFor(empty, config.QueryProfile)
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
	request, err := verify.DecodeExperimentalBatchEntryRequest(raw)
	if err != nil || request.Context != *selectedQuery {
		return finish(70, "request", "invalid_identity")
	}
	raw, err = readExperimentalCLIFile(fs.Arg(0), maxExperimentalBundleBytes, openExperimentalCLIFile)
	if err != nil {
		return finish(70, "bundle", "invalid_input")
	}
	bundle, err := decodeExperimentalCLIBundle(raw, config.HeaderPolicy.MaxBatchHeaders, *compare)
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
	query, err := verify.NewExperimentalBatchEntryQuery(state, config.QueryProfile, *selectedQuery)
	if err != nil {
		return finish(70, "query", "invalid_configuration")
	}
	var result verify.ExperimentalBatchEntryResult
	if *compare {
		result, err = query.QueryWithGateway(request, bundle.Witness, *bundle.Gateway)
	} else {
		result, err = query.QueryWitness(request, bundle.Witness)
	}
	if err != nil {
		code, category := experimentalBatchQueryError(err)
		return finish(code, "query", category)
	}
	report.HeaderContext, report.QueryContext, report.Result = &headerContext, &queryContext, &result
	return finish(0, "", "")
}

func experimentalBatchQueryError(err error) (int, string) {
	switch {
	case errors.Is(err, verify.ErrExperimentalBatchEntryAbsent):
		return 2, "typed_value_absent"
	case errors.Is(err, proof.ErrCandidateSMTBounds), errors.Is(err, proof.ErrCandidateBatchEntryBounds):
		return 2, "unsupported_bounds"
	case errors.Is(err, verify.ErrExperimentalV3HeaderUnavailable), errors.Is(err, verify.ErrExperimentalV3Depth):
		return 2, "outside_owned_scope"
	case errors.Is(err, verify.ErrExperimentalBatchEntryContext), errors.Is(err, verify.ErrExperimentalBatchEntryTip), errors.Is(err, verify.ErrExperimentalV3HeaderMismatch):
		return 1, "query_identity_mismatch"
	case errors.Is(err, verify.ErrExperimentalBatchEntryGateway):
		return 1, "gateway_mismatch"
	case errors.Is(err, verify.ErrExperimentalBatchEntrySourceRule):
		return 1, "source_rule_mismatch"
	case errors.Is(err, verify.ErrExperimentalBatchEntryWitnessRoot), errors.Is(err, verify.ErrExperimentalBatchEntryWitnessValue), errors.Is(err, verify.ErrExperimentalBatchEntryCanonical), errors.Is(err, proof.ErrCandidateSMTEncoding), errors.Is(err, proof.ErrCandidateSMTPath), errors.Is(err, proof.ErrCandidateSMTMismatch), errors.Is(err, proof.ErrCandidateBatchEntryEncoding):
		return 1, "invalid_witness"
	default:
		return 70, "operational"
	}
}

func finishExperimentalBatch(report experimentalCLIReport, code int, stdout, stderr io.Writer) int {
	report.ExitCode = code
	switch code {
	case 0:
		report.Status = "matched"
		if report.Command == experimentalConfigCommand {
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

func writeExperimentalBatch(destination, diagnostics io.Writer, raw []byte, code int) int {
	n, err := destination.Write(raw)
	if err != nil || n != len(raw) {
		_, _ = fmt.Fprintln(diagnostics, "experimental query: cannot write output")
		return 70
	}
	return code
}
