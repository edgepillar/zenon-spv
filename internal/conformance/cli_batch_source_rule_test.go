// SPDX-License-Identifier: MIT

package conformance_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Reuses the enclosing workflow's fresh executable; no additional build or
// provider read. The negative cohort is mathematical data with public unit
// signatures, never original-node, selected-devnet or production evidence.
func runCompiledBatchSourceRuleControls(t *testing.T, binary string, configRaw json.RawMessage,
	selected verify.ExperimentalBatchContextRequest, headerPin, bundlePath string) {
	t.Helper()
	t.Run("version-2-source-rule-positive", func(t *testing.T) {
		var config map[string]json.RawMessage
		var profile verify.ExperimentalBatchContextProfile
		if json.Unmarshal(configRaw, &config) != nil || json.Unmarshal(config["query_profile"], &profile) != nil {
			t.Fatal("positive source-rule configuration")
		}
		profile.Version, profile.Entry.Version, profile.Entry.SourceRule = 2, 2, verify.ExperimentalBatchEntrySourceRule
		config["query_profile"], _ = json.Marshal(profile)
		selected.Context = collectionWorkflowHash(t, "478088778573e6080c550c686c7434928bf4f16d0306daea6fe5416090cb91fd")
		dir := t.TempDir()
		c := writeCLIJSON(t, dir, "source-rule-config.json", config)
		r := writeCLIJSON(t, dir, "source-rule-request.json", selected)
		args := []string{"query-experimental-batch-context", "--config", c, "--request", r,
			"--expect-header-context", headerPin, "--expect-query-context", hex.EncodeToString(selected.Context[:]), bundlePath}
		runCompiledSourceRuleReport(t, binary, args, true, "EXPERIMENTAL_CONFIGURED_HEADER_THREE_ROW_MEMBERSHIP")
	})

	raw, err := os.ReadFile("../testdata/conformance/batch-entry-source-rule-invalid-context.json")
	sum := sha256.Sum256(raw)
	if err != nil || len(raw) != 17527 || hex.EncodeToString(sum[:]) != "12a60cba21d84a97cf4e584cfc016d871279f17814c087af1238d28d653825b8" {
		t.Fatal("negative source-rule fixture changed", err)
	}
	var fixture struct {
		Config    map[string]json.RawMessage
		Request   verify.ExperimentalBatchContextRequest
		Momentums []json.RawMessage
		Witnesses struct {
			Root chain.Hash `json:"root_hex"`
			Rows []struct {
				Name  string
				Value string `json:"value_hex"`
				Proof string `json:"proof_hex"`
			}
		}
	}
	if json.Unmarshal(raw, &fixture) != nil || len(fixture.Witnesses.Rows) != 3 {
		t.Fatal("negative source-rule workflow framing")
	}
	var base verify.ExperimentalBatchContextProfile
	if json.Unmarshal(fixture.Config["query_profile"], &base) != nil {
		t.Fatal("negative profile")
	}
	witnesses := map[string]any{}
	for _, row := range fixture.Witnesses.Rows {
		value, e1 := hex.DecodeString(row.Value)
		encoded, e2 := hex.DecodeString(row.Proof)
		if e1 != nil || e2 != nil {
			t.Fatal("negative witness bytes")
		}
		witnesses[row.Name] = map[string]any{"root": fixture.Witnesses.Root, "value": value, "proof": encoded}
	}
	for _, mode := range []string{"entry", "context"} {
		for _, version := range []uint32{1, 2} {
			label := mode + map[uint32]string{1: "-legacy-preserved", 2: "-source-rule-refused"}[version]
			t.Run(label, func(t *testing.T) {
				profile := base
				profile.Version, profile.Entry.Version = version, version
				if version == 1 {
					profile.Entry.SourceRule = ""
				}
				config := make(map[string]json.RawMessage, len(fixture.Config))
				for k, v := range fixture.Config {
					config[k] = v
				}
				command := "query-experimental-batch-context"
				scope := "EXPERIMENTAL_CONFIGURED_HEADER_THREE_ROW_MEMBERSHIP"
				pin := map[uint32]string{1: "0eebc128c2e065ad1ebb898ce4343b43763ee1ff81fffdaf93131f9f5c77beab",
					2: "478088778573e6080c550c686c7434928bf4f16d0306daea6fe5416090cb91fd"}[version]
				bundle := map[string]any{"version": 1, "momentums": fixture.Momentums, "witnesses": witnesses}
				config["query_profile"], _ = json.Marshal(profile)
				if mode == "entry" {
					command, scope = "query-experimental-batch-entry", "EXPERIMENTAL_CONFIGURED_HEADER_MEMBERSHIP"
					pin = map[uint32]string{1: "6ee3ee803ee6fe810940d265bb098c751de8ba4a12de128646c4f8e8aa8847a0",
						2: "93cdf8e13f5a4251b6c6d978d41e79550399482b7b8f47979a2e962b13107c25"}[version]
					config["query_profile"], _ = json.Marshal(profile.Entry)
					delete(bundle, "witnesses")
					bundle["witness"] = witnesses["batch_entry"]
				}
				request := fixture.Request
				request.Context = collectionWorkflowHash(t, pin)
				dir := t.TempDir()
				c := writeCLIJSON(t, dir, "configuration.json", config)
				r := writeCLIJSON(t, dir, "request.json", request)
				b := writeCLIJSON(t, dir, "provider.json", bundle)
				guards := []func(){protectCLIState(t, c), protectCLIState(t, r), protectCLIState(t, b)}
				args := []string{command, "--config", c, "--request", r,
					"--expect-header-context", headerPin, "--expect-query-context", pin, b}
				runCompiledSourceRuleReport(t, binary, args, version == 1, scope)
				for _, guard := range guards {
					guard()
				}
			})
		}
	}
}

func runCompiledSourceRuleReport(t *testing.T, binary string, args []string, accepted bool, scope string) {
	t.Helper()
	observed := runQueryCLI(t, binary, args...)
	var report struct {
		Status      string
		Scope       string
		ExitCode    int `json:"exit_code"`
		Result      json.RawMessage
		Headers     struct{ Outcome string }
		Error       *struct{ Stage, Category string }
		Persistence string
		RPCRequests int  `json:"rpc_requests"`
		Production  bool `json:"production_state_value_guarantee"`
	}
	if json.Unmarshal(observed.stdout, &report) != nil || len(observed.stderr) != 0 ||
		report.ExitCode != observed.code || report.Headers.Outcome != "ACCEPT" ||
		report.Scope != scope || report.Persistence != "read_only" || report.RPCRequests != 0 || report.Production {
		t.Fatal("source-rule CLI scope or header result differs", observed.code)
	}
	if accepted {
		if observed.code != 0 || report.Status != "matched" || string(report.Result) == "null" || report.Error != nil {
			t.Fatal("legacy or explicit positive source policy failed", observed.code)
		}
	} else if observed.code != 1 || string(report.Result) != "null" || report.Error == nil ||
		report.Error.Stage != "query" || report.Error.Category != "source_rule_mismatch" {
		t.Fatal("source-policy rejection exposed a partial result or wrong category", observed.code)
	}
}
