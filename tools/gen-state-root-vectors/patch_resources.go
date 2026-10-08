//go:build candidate_patch_resources && (darwin || linux)

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zenon-network/go-zenon/common/types"
)

const resourcePeakMethod = "getrusage(RUSAGE_SELF) immediately after importApply and stats sampling, before output binding; process lifetime high water includes startup, provenance, resident input, initial binding and pre-operation GC"

type patchResourceInput struct {
	input  importInput
	target map[string]string
	caps   importTargetLimits
}

func resourceRecords(count, valueBytes int) []byte {
	raw := []byte{}
	for i := 0; i < count; i++ {
		raw = append(raw, 1)
		raw = binary.AppendUvarint(raw, 32)
		raw = append(raw, decodeKey(uint32(i+1))...)
		raw = binary.AppendUvarint(raw, uint64(valueBytes))
		raw = append(raw, bytes.Repeat([]byte{byte(i%251 + 1)}, valueBytes)...)
	}
	return raw
}

func resourceTarget(count int) map[string]string {
	target := map[string]string{}
	for i := 0; i < count; i++ {
		target[hex.EncodeToString(decodeKey(uint32(i+1)))] = hex.EncodeToString(decodeValue(uint64(i + 1)))
	}
	return target
}

// These literal families are rebuilt independently in the Python oracle. Input
// construction, selection and binding are outside every operation measurement.
func patchResourceFamilies() []string {
	return []string{"empty-owned-empty", "records-64-owned-128", "records-256-owned-1024", "records-1024-owned-4096",
		"raw-ceiling-transient-hex-refusal", "target-entries-4096-noop", "target-entries-4097-noop", "target-hex-ceiling-noop",
		"put-then-delete", "delete-then-put", "selection-mismatch-before-clone", "injected-replay-error-complete"}
}

func patchResourceInputFor(name string) patchResourceInput {
	raw, count, target, caps, fault := []byte{}, uint64(0), resourceTarget(0), importTargetCeilings, "none"
	switch name {
	case "empty-owned-empty":
	case "records-64-owned-128":
		raw, count, target = resourceRecords(64, 970), 64, resourceTarget(128)
	case "records-256-owned-1024", "selection-mismatch-before-clone", "injected-replay-error-complete":
		raw, count, target = resourceRecords(256, 970), 256, resourceTarget(1024)
		if name == "injected-replay-error-complete" {
			fault = "replay-error-complete"
		}
	case "records-1024-owned-4096":
		raw, count, target = resourceRecords(1024, 32), 1024, resourceTarget(4096)
	case "raw-ceiling-transient-hex-refusal":
		raw = resourceRecords(15, 65500)
		last := resourceRecords(1, 65484)
		copy(last[2:34], decodeKey(16))
		raw, count = append(raw, last...), 16
		if len(raw) != 1<<20 {
			panic("wrong literal raw ceiling family")
		}
	case "target-entries-4096-noop", "target-entries-4097-noop":
		entries := 4096
		if name == "target-entries-4097-noop" {
			entries++
		}
		for i := 0; i < entries; i++ {
			target[fmt.Sprintf("%08x", i)] = ""
		}
	case "target-hex-ceiling-noop":
		target = map[string]string{"": strings.Repeat("00", 1<<19)}
	case "put-then-delete", "delete-then-put":
		raw, count = targetDump(name)
		target, caps = importInitial(), importTargetLimits{3, 384}
	default:
		panic("unselected patch resource family")
	}
	chosen := importSelection{name, uint64(len(raw)), count, types.NewHash(raw).String()}
	if name == "selection-mismatch-before-clone" {
		chosen.ChangesHash = types.ZeroHash.String()
	}
	return patchResourceInput{importInput{decodeInput{name, raw}, importCeilings, chosen, fault}, target, caps}
}

// Canonical unsigned fixture binding, never an SMT root or an authenticated
// state identifier. UseNumber also keeps nested struct integer spelling exact.
func resourceJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic any
	if err = decoder.Decode(&generic); err != nil {
		panic(err)
	}
	raw, err = json.Marshal(generic)
	if err != nil {
		panic(err)
	}
	return raw
}

func resourceHash(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func resourceCallbacks(events []importEvent) any {
	manifest := []any{}
	for _, event := range events {
		manifest = append(manifest, map[string]any{"operation": event.Operation, "key": event.Key, "value": event.Value})
	}
	return map[string]any{"count": len(events), "manifest_sha256": resourceHash(resourceJSON(manifest))}
}

func patchResourceChild(item patchResourceInput, mode string, repetition int) any {
	// Keep these inputs and initial binding live across one pre-operation GC.
	// Cloning the map shares its immutable string payloads; it is not a deep
	// string copy. All importApply validation, owned raw copy, node constructor,
	// detached map clone, replay and replacement lie inside the timing interval.
	before := targetSummary(item.target)
	rawBefore := resourceHash(item.input.raw)
	runtime.GC()
	var first, last runtime.MemStats
	if mode == "allocation" {
		runtime.ReadMemStats(&first)
	}
	start := time.Now()
	result := importApply(item.input, item.target, item.caps)
	elapsed := time.Since(start).Nanoseconds()
	if mode == "allocation" {
		runtime.ReadMemStats(&last)
	}
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		panic(err)
	}
	peak := usage.Maxrss
	if runtime.GOOS == "linux" {
		peak *= 1024
	}
	verdict := "STAGED"
	if result.refusal != "" {
		verdict = "REJECTED"
	}
	conformance := map[string]any{"name": item.input.name, "raw_bytes": len(item.input.raw), "raw_sha256": rawBefore,
		"source_after_sha256": resourceHash(item.input.raw), "limits": item.input.limits, "selection": item.input.selection,
		"target_limits": item.caps, "injected_fault": item.input.fault, "preflight_records": len(result.stage.expected),
		"raw_copies": result.rawCopies, "constructor_calls": result.constructorCalls, "default_replay_calls": result.replayCalls,
		"target_clone_calls": result.cloneCalls, "target_cloned_entries": result.clonedEntries,
		"staging_callbacks": resourceCallbacks(result.stage.events), "staging_target": targetSummary(result.stage.state),
		"target_before": before, "target_after": targetSummary(result.target), "original_alias_after": targetSummary(item.target),
		"target_replacements": result.replacements, "research_import_result": verdict, "refusal": result.refusal, "consumer_result": "REFUSED"}
	measurement := map[string]any{"case": item.input.name, "mode": mode, "repetition": repetition, "elapsed_ns": elapsed,
		"go_total_alloc_delta_bytes": nil, "go_mallocs_delta": nil, "go_gc_cycles": nil,
		"process_peak_rss_bytes": peak, "process_peak_rss_method": resourcePeakMethod,
		"conformance_sha256": resourceHash(resourceJSON(conformance)), "platform": runtime.GOOS + "/" + runtime.GOARCH, "go_version": runtime.Version()}
	if mode == "allocation" {
		measurement["go_total_alloc_delta_bytes"] = last.TotalAlloc - first.TotalAlloc
		measurement["go_mallocs_delta"] = last.Mallocs - first.Mallocs
		measurement["go_gc_cycles"] = uint64(last.NumGC - first.NumGC)
	}
	runtime.KeepAlive(item)
	runtime.KeepAlive(before)
	return map[string]any{"conformance": conformance, "measurement": measurement}
}

func generatePatchResources() any {
	exe, err := os.Executable()
	if err != nil {
		panic(err)
	}
	cases, samples := []any{}, []any{}
	for _, name := range patchResourceFamilies() {
		var selected []byte
		for repetition := 0; repetition < 3; repetition++ {
			for _, mode := range []string{"plain", "allocation"} {
				command := exec.Command(exe, "--verified-node-tree", nodeTree, "--patch-resource-child", name, mode, strconv.Itoa(repetition))
				var output, diagnostics bytes.Buffer
				command.Stdout, command.Stderr = &output, &diagnostics
				err := command.Run()
				// Preserve each original completed or failed child outcome before
				// interpreting it. The offline driver seals stderr on all exits.
				code := 0
				if err != nil {
					code = -1
					if command.ProcessState != nil {
						code = command.ProcessState.ExitCode()
					}
				}
				ledger := map[string]any{"case": name, "mode": mode, "repetition": repetition, "actual_exit": code,
					"stdout": output.String(), "stderr": diagnostics.String()}
				fmt.Fprintln(os.Stderr, string(resourceJSON(ledger)))
				if err != nil || diagnostics.Len() != 0 {
					panic("patch resource child failed; preserve its first outcome")
				}
				var record map[string]any
				if err := json.Unmarshal(output.Bytes(), &record); err != nil || len(record) != 2 {
					panic("invalid patch resource child record")
				}
				binding := resourceJSON(record["conformance"])
				if selected == nil {
					selected = binding
					cases = append(cases, record["conformance"])
				} else if !bytes.Equal(binding, selected) {
					panic("patch resource worker conformance differs")
				}
				samples = append(samples, record["measurement"])
			}
		}
	}
	return map[string]any{"format_version": 1, "kind": "candidate-patch-import-resource-research",
		"source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"scope": map[string]bool{"synthetic": true, "unsigned": true, "whole_owned_importApply_measured": true,
			"actual_NewPatchFromDump_executed": true, "default_Batch_Replay_executed": true, "initial_and_transient_target_limits_executed": true,
			"single_exclusive_caller": true, "fresh_child_per_sample": true, "resident_inputs_before_measurement": true,
			"variable_resource_samples_separate_from_conformance": true, "fixture_and_report_work_inside_operation_timing": false,
			"map_clone_deep_copies_string_payloads": false, "node_database_opened": false, "actual_NodeTree_executed": false,
			"authenticated_snapshot_import": false, "shared_writer_atomicity": false, "crash_durability": false,
			"production_resource_budgets_qualified": false, "network_execution": false, "full_node_started": false,
			"signing": false, "transactions": false, "profile_agreed": false, "network_activation_authenticated": false,
			"runtime_state_proof_acceptance": false}, "cases": cases, "measurements": samples}
}

func init() {
	patchResourceGenerator = generatePatchResources
	if len(os.Args) > 3 && os.Args[3] == "--patch-resource-child" {
		if len(os.Args) != 7 || os.Args[1] != "--verified-node-tree" || os.Args[2] != nodeTree {
			panic("unselected patch resource child")
		}
		info, ok := debug.ReadBuildInfo()
		selected := false
		if ok {
			for _, dependency := range info.Deps {
				if dependency.Path == "github.com/zenon-network/go-zenon" {
					selected = dependency.Version == "v0.0.0" && dependency.Replace != nil && dependency.Replace.Path == "../reference-node" &&
						(dependency.Replace.Version == "" || dependency.Replace.Version == "(devel)")
				}
			}
		}
		repetition, err := strconv.Atoi(os.Args[6])
		if !selected || err != nil || repetition < 0 || repetition >= 3 || (os.Args[5] != "plain" && os.Args[5] != "allocation") {
			panic("unselected patch resource source or measurement mode")
		}
		for _, name := range patchResourceFamilies() {
			if name == os.Args[4] {
				if err := json.NewEncoder(os.Stdout).Encode(patchResourceChild(patchResourceInputFor(name), os.Args[5], repetition)); err != nil {
					panic(err)
				}
				os.Exit(0)
			}
		}
		panic("unselected patch resource family")
	}
}
