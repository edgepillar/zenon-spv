package main

import (
	"bytes"
	"encoding/json"
)

var queryCLIBuildReportCommands = [...]string{
	"zenon-spv", "fetch-bundle", "derive-producer-schedule", "derive-checkpoints",
	"verify-mainnet-genesis", "consume-query-report", "observe-block",
}

type queryCLIBuildBatchReport struct {
	SchemaVersion int                   `json:"schema_version"`
	Commands      int                   `json:"commands"`
	Individual    int                   `json:"individual_go_build_invocations"`
	Batch         int                   `json:"batch_go_build_invocations"`
	Rebuild       int                   `json:"rebuild_go_build_invocations"`
	Parallelism   int                   `json:"build_parallelism"`
	Equal         bool                  `json:"binary_bytes_equal"`
	Independent   bool                  `json:"independent_paths"`
	Mutation      bool                  `json:"private_mutation_isolated"`
	Fresh         bool                  `json:"fresh_rebuild"`
	Exports       bool                  `json:"existing_exports_unchanged"`
	ReferenceNS   int64                 `json:"reference_elapsed_ns"`
	BatchNS       int64                 `json:"batch_elapsed_ns"`
	Binaries      []queryCLIBuildOutput `json:"binaries"`
}

type queryCLIBuildOutput struct {
	Command string `json:"command"`
	SHA256  string `json:"sha256"`
	Bytes   int64  `json:"bytes"`
}

// The grouped build control emits dynamic executable identities and timings.
// Retain only its exact public schema, with no paths or unparsed output.
func validQueryCLIBuildBatchReport(raw []byte) bool {
	var report queryCLIBuildBatchReport
	if json.Unmarshal(raw, &report) != nil ||
		report.SchemaVersion != 1 || report.Commands != len(queryCLIBuildReportCommands) ||
		report.Individual != report.Commands || report.Batch != 1 || report.Rebuild != 1 || report.Parallelism != 1 ||
		!report.Equal || !report.Independent || !report.Mutation || !report.Fresh || !report.Exports ||
		report.ReferenceNS <= 0 || report.BatchNS <= 0 || len(report.Binaries) != report.Commands {
		return false
	}
	for i, binary := range report.Binaries {
		if binary.Command != queryCLIBuildReportCommands[i] || !hexDigest(binary.SHA256, 64) ||
			binary.Bytes <= 0 || binary.Bytes > candidateBinaryLimit {
			return false
		}
	}
	canonical, err := json.Marshal(report)
	return err == nil && bytes.Equal(canonical, raw)
}
