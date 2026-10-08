//go:build candidate_patch_targets

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zenon-network/go-zenon/common/types"
)

type targetInput struct {
	name   string
	input  importInput
	target map[string]string
	limits importTargetLimits
}

func targetDump(name string) ([]byte, uint64) {
	var raw []byte
	put := func(key uint32, value []byte) {
		raw = append(raw, 1, 32)
		raw = append(raw, decodeKey(key)...)
		raw = append(raw, byte(len(value)))
		raw = append(raw, value...)
	}
	del := func(key uint32) { raw = append(append(raw, 0, 32), decodeKey(key)...) }
	switch name {
	case "put-then-delete":
		put(8, decodeValue(9))
		del(2)
	case "delete-then-put":
		del(2)
		put(8, decodeValue(9))
	case "grow-then-delete":
		put(1, make([]byte, 33))
		del(2)
	case "replace-smaller-then-grow":
		put(1, []byte{})
		put(1, decodeValue(9))
	case "empty-key-put-delete":
		raw = []byte{1, 0, 0, 0, 0}
	default:
		raw = importSelectedDump(name)
		return raw, importSelect(name).Records
	}
	return raw, 2
}

func targetInputs() []targetInput {
	inputs := []targetInput{}
	defaults := importTargetLimits{8, 1024}
	add := func(name, dump, fault string, target map[string]string, limits importTargetLimits) {
		raw, count := targetDump(dump)
		selected := importSelection{dump, uint64(len(raw)), count, types.NewHash(raw).String()}
		inputs = append(inputs, targetInput{name, importInput{decodeInput{name, raw}, importDefaults, selected, fault}, target, limits})
	}
	add("default-complete", "complete", "none", importInitial(), defaults)
	add("exact-target-bounds", "complete", "none", importInitial(), importTargetLimits{3, 384})
	add("empty-initial-target", "complete", "none", map[string]string{}, importTargetLimits{2, 256})
	add("initial-entry-short", "complete", "none", importInitial(), importTargetLimits{2, 384})
	add("initial-hex-short", "complete", "none", importInitial(), importTargetLimits{3, 383})
	for field, cap := range []uint64{importTargetCeilings.Entries, importTargetCeilings.HexBytes} {
		for _, value := range []uint64{0, cap + 1} {
			limits := defaults
			if field == 0 {
				limits.Entries = value
			} else {
				limits.HexBytes = value
			}
			add(fmt.Sprintf("invalid-target-limit-%d-%d", field, value), "complete", "none", importInitial(), limits)
		}
	}
	for _, field := range []string{"key", "value"} {
		for _, spelling := range []string{"0", "GG", "Aa"} {
			target := map[string]string{"00": "00"}
			if field == "key" {
				target = map[string]string{spelling: "00"}
			} else {
				target["00"] = spelling
			}
			add("invalid-"+field+"-"+spelling, "complete", "none", target, defaults)
		}
	}
	for _, name := range []string{"put-then-delete", "delete-then-put", "grow-then-delete", "replace-smaller-then-grow"} {
		add(name, name, "none", importInitial(), importTargetLimits{3, 384})
	}
	add("new-entry-with-room", "put-then-delete", "none", importInitial(), importTargetLimits{4, 512})
	add("value-growth-with-room", "grow-then-delete", "none", importInitial(), importTargetLimits{3, 386})
	for _, name := range []string{"empty", "empty-delete", "empty-put", "overlong-empty-put", "overlong-complete", "duplicate-9", "duplicate-10", "empty-key-put-delete"} {
		add(name+"-selected", name, "none", importInitial(), importTargetLimits{4, 384})
	}
	for _, fault := range []string{"load-error", "load-nil", "replay-error-first", "replay-error-complete", "replay-omit-last", "replay-extra", "replay-wrong-value", "mutate-owned-after-load", "mutate-source-after-load"} {
		add(fault, "complete", fault, importInitial(), defaults)
	}
	add("malformed-raw-before-clone", "complete", "none", importInitial(), defaults)
	inputs[len(inputs)-1].input.raw = append(inputs[len(inputs)-1].input.raw, 2)
	add("wrong-selection-before-clone", "complete", "none", importInitial(), defaults)
	inputs[len(inputs)-1].input.selection.ChangesHash = types.ZeroHash.String()
	add("raw-cap-before-copy", "complete", "none", importInitial(), defaults)
	inputs[len(inputs)-1].input.limits.RawBytes = 167
	add("invalid-raw-limit-before-copy", "complete", "none", importInitial(), defaults)
	inputs[len(inputs)-1].input.limits.RawBytes = 0
	for _, count := range []uint64{4096, 4097} {
		target := map[string]string{}
		for i := uint64(0); i < count; i++ {
			target[fmt.Sprintf("%08x", i)] = ""
		}
		add(fmt.Sprintf("target-entries-%d", count), "empty", "none", target, importTargetCeilings)
	}
	for _, size := range []uint64{1 << 20, (1 << 20) + 2} {
		target := map[string]string{"": strings.Repeat("00", int(size/2))}
		add(fmt.Sprintf("target-hex-bytes-%d", size), "empty", "none", target, importTargetCeilings)
	}
	return inputs
}

// Bind every complete, independently reconstructed map, including large cap
// cases, without embedding repeated megabytes in the finite fixture document.
func targetSummary(target map[string]string) any {
	raw, err := json.Marshal(decodeManifest(target))
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(raw)
	size := uint64(0)
	for key, value := range target {
		size += uint64(len(key)) + uint64(len(value))
	}
	return map[string]any{"entries": len(target), "hex_bytes": size, "manifest_sha256": hex.EncodeToString(digest[:])}
}

func targetCase(input targetInput) any {
	before := append([]byte{}, input.input.raw...)
	original := targetSummary(input.target)
	execution := importApply(input.input, input.target, input.limits)
	result := "REJECTED"
	if execution.refusal == "" {
		result = "STAGED"
	}
	return map[string]any{"name": input.name, "input": hex.EncodeToString(before), "source_after": hex.EncodeToString(input.input.raw),
		"limits": input.input.limits, "selection": input.input.selection, "target_limits": input.limits, "injected_fault": input.input.fault,
		"preflight_records": len(execution.stage.expected), "raw_copies": execution.rawCopies,
		"constructor_calls": execution.constructorCalls, "default_replay_calls": execution.replayCalls,
		"target_clone_calls": execution.cloneCalls, "target_cloned_entries": execution.clonedEntries,
		"staging_callbacks": execution.stage.events, "staging_target": targetSummary(execution.stage.state),
		"target_before": original, "target_after": targetSummary(execution.target), "original_alias_after": targetSummary(input.target),
		"target_replacements": execution.replacements, "research_import_result": result, "refusal": execution.refusal, "consumer_result": "REFUSED"}
}

func generatePatchTargets() any {
	cases := []any{}
	for _, input := range targetInputs() {
		cases = append(cases, targetCase(input))
	}
	return map[string]any{"format_version": 1, "kind": "candidate-patch-target-research",
		"source":                map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"target_limits_ceiling": importTargetCeilings, "default_target_limits": importTargetLimits{8, 1024},
		"scope": map[string]bool{"synthetic": true, "unsigned": true, "actual_NewPatchFromDump_executed": true,
			"default_Batch_Replay_executed": true, "injected_constructor_and_replay_faults": true,
			"initial_and_transient_target_limits_executed": true, "owned_memory_map_replacement_executed": true,
			"cloning_after_complete_selection_and_constructor_checks": true, "single_exclusive_caller": true,
			"hex_payload_cap_is_whole_process_memory_budget": false, "decoder_panic_recovery_used": false,
			"node_database_opened": false, "actual_NodeTree_executed": false, "production_caller_execution": false,
			"authenticated_snapshot_import": false, "shared_writer_atomicity": false, "crash_durability": false,
			"resource_measurements_executed": false, "network_execution": false, "full_node_started": false,
			"signing": false, "transactions": false, "profile_agreed": false, "network_activation_authenticated": false,
			"runtime_state_proof_acceptance": false}, "cases": cases}
}

func init() { patchTargetGenerator = generatePatchTargets }
