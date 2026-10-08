//go:build candidate_patch_import

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

// This private research contract imports only a selected patch into an owned
// in-memory map. It is not a snapshot importer, typed state verifier or runtime
// API. The caller is exclusive; no shared writer, disk or crash guarantees apply.
type importLimits struct {
	RawBytes   uint64 `json:"raw_bytes"`
	Records    uint64 `json:"records"`
	KeyBytes   uint64 `json:"key_bytes"`
	ValueBytes uint64 `json:"value_bytes"`
}

var importCeilings = importLimits{1 << 20, 1024, 4096, 65536}
var importDefaults = importLimits{1024, 8, 64, 128}

// HexBytes counts key/value string payloads, not Go map/interpreter overhead or
// decoded state bytes. These research caps do not qualify a resource budget.
type importTargetLimits struct {
	Entries  uint64 `json:"entries"`
	HexBytes uint64 `json:"hex_bytes"`
}

var importTargetCeilings = importTargetLimits{4096, 1 << 20}

func importTargetBounds(limits importTargetLimits) bool {
	return limits.Entries > 0 && limits.Entries <= importTargetCeilings.Entries &&
		limits.HexBytes > 0 && limits.HexBytes <= importTargetCeilings.HexBytes
}

func importHex(text string) bool {
	if len(text)%2 != 0 {
		return false
	}
	for i := range text {
		if !('0' <= text[i] && text[i] <= '9') && !('a' <= text[i] && text[i] <= 'f') {
			return false
		}
	}
	return true
}

// Validate without copying the caller's map. Exclusivity for this complete
// operation is a caller precondition, not a lock or a shared-writer guarantee.
func importTargetPreflight(target map[string]string, limits importTargetLimits) (uint64, string) {
	if !importTargetBounds(limits) {
		return 0, "invalid_target_limits"
	}
	if uint64(len(target)) > limits.Entries {
		return 0, "target_entry_limit"
	}
	total := uint64(0)
	for key, value := range target {
		for _, part := range []string{key, value} {
			if uint64(len(part)) > limits.HexBytes-total {
				return 0, "target_hex_limit"
			}
			total += uint64(len(part))
		}
	}
	// Check spelling only after the complete size bound, so large malformed
	// strings cannot force a traversal outside the selected payload cap.
	for key, value := range target {
		if !importHex(key) || !importHex(value) {
			return 0, "invalid_target_encoding"
		}
	}
	return total, ""
}

type importSelection struct {
	Name        string `json:"name"`
	Bytes       uint64 `json:"bytes"`
	Records     uint64 `json:"records"`
	ChangesHash string `json:"changes_hash"`
}

type importEvent struct {
	Operation string  `json:"operation"`
	Key       string  `json:"key"`
	Value     *string `json:"value"`
}

type importInput struct {
	decodeInput
	limits    importLimits
	selection importSelection
	fault     string
}

// Select literal record bytes before invoking the candidate constructor. Raw
// record spelling is part of the selection; equivalent varints are not rewritten.
func importSelectedDump(name string) []byte {
	complete := append([]byte{1, 32}, decodeKey(1)...)
	complete = append(append(complete, 32), decodeValue(91)...)
	complete = append(append(complete, 0, 32), decodeKey(2)...)
	complete = append(append(complete, 1, 32), decodeKey(8)...)
	complete = append(append(complete, 32), decodeValue(9)...)
	switch name {
	case "complete":
		return complete
	case "empty":
		return []byte{}
	case "empty-delete":
		return []byte{0, 0}
	case "empty-put":
		return []byte{1, 0, 0}
	case "overlong-empty-put":
		return []byte{1, 0x80, 0, 0x80, 0}
	case "overlong-complete":
		raw := append([]byte{1, 0xa0, 0}, decodeKey(1)...)
		raw = append(append(raw, 0xa0, 0), decodeValue(91)...)
		return append(raw, complete[67:]...)
	case "duplicate-9", "duplicate-10":
		amount := uint64(9)
		if name == "duplicate-10" {
			amount = 10
		}
		raw := append(append(complete, 1, 32), decodeKey(8)...)
		return append(append(raw, 32), decodeValue(amount)...)
	default:
		panic("unselected research dump")
	}
}

func importSelect(name string) importSelection {
	raw := importSelectedDump(name)
	count := uint64(1)
	switch name {
	case "complete", "overlong-complete":
		count = 3
	case "duplicate-9", "duplicate-10":
		count = 4
	case "empty":
		count = 0
	}
	return importSelection{name, uint64(len(raw)), count, types.NewHash(raw).String()}
}

func importInputs() []importInput {
	inputs := []importInput{}
	selected := importSelect("complete")
	for _, input := range decodeInputs() {
		inputs = append(inputs, importInput{input, importDefaults, selected, "none"})
	}
	add := func(name string, limits importLimits, selection importSelection, fault string) {
		inputs = append(inputs, importInput{decodeInput{name, importSelectedDump(selection.Name)}, limits, selection, fault})
	}
	add("exact-all-bounds", importLimits{168, 3, 32, 32}, selected, "none")
	for field, value := range []uint64{167, 2, 31, 31} {
		limits := importDefaults
		pointers := []*uint64{&limits.RawBytes, &limits.Records, &limits.KeyBytes, &limits.ValueBytes}
		*pointers[field] = value
		add([]string{"raw-limit-short", "record-limit-short", "key-limit-short", "value-limit-short"}[field], limits, selected, "none")
	}
	for field, cap := range []uint64{importCeilings.RawBytes, importCeilings.Records, importCeilings.KeyBytes, importCeilings.ValueBytes} {
		for _, value := range []uint64{0, cap + 1} {
			limits := importDefaults
			pointers := []*uint64{&limits.RawBytes, &limits.Records, &limits.KeyBytes, &limits.ValueBytes}
			*pointers[field] = value
			add(fmt.Sprintf("invalid-limit-%d-%d", field, value), limits, selected, "none")
		}
	}
	for _, name := range []string{"wrong-byte-count", "wrong-changes-hash", "wrong-record-count"} {
		selection := selected
		switch name {
		case "wrong-byte-count":
			selection.Bytes--
		case "wrong-changes-hash":
			selection.ChangesHash = types.ZeroHash.String()
		case "wrong-record-count":
			selection.Records--
		}
		add(name, importDefaults, selection, "none")
	}
	for _, name := range []string{"empty", "empty-delete", "empty-put", "overlong-empty-put", "overlong-complete", "duplicate-9", "duplicate-10"} {
		add(name+"-selected", importDefaults, importSelect(name), "none")
	}
	for _, fault := range []string{"load-error", "load-nil", "replay-error-first", "replay-error-complete", "replay-omit-last", "replay-extra", "replay-wrong-value", "mutate-owned-after-load", "mutate-source-after-load"} {
		add(fault, importDefaults, selected, fault)
	}
	return inputs
}

func importBounds(limits importLimits) bool {
	return limits.RawBytes > 0 && limits.RawBytes <= importCeilings.RawBytes &&
		limits.Records > 0 && limits.Records <= importCeilings.Records &&
		limits.KeyBytes > 0 && limits.KeyBytes <= importCeilings.KeyBytes &&
		limits.ValueBytes > 0 && limits.ValueBytes <= importCeilings.ValueBytes
}

// Compare unsigned lengths with bounded remaining bytes before int conversion
// or slicing. No signed addition of an attacker-selected length is performed.
func importPreflight(raw []byte, limits importLimits) ([]importEvent, string) {
	events := []importEvent{}
	if !importBounds(limits) {
		return events, "invalid_limits"
	}
	if uint64(len(raw)) > limits.RawBytes {
		return events, "raw_limit"
	}
	offset := 0
	field := func(cap uint64, name string) ([]byte, string) {
		number, size := binary.Uvarint(raw[offset:])
		if size <= 0 {
			return nil, "invalid_varint"
		}
		offset += size
		if number > cap {
			return nil, name + "_limit"
		}
		if number > uint64(len(raw)-offset) {
			return nil, "truncated_" + name
		}
		end := offset + int(number)
		data := raw[offset:end]
		offset = end
		return data, ""
	}
	for offset < len(raw) {
		if uint64(len(events)) == limits.Records {
			return events, "record_limit"
		}
		kind := raw[offset]
		offset++
		if kind > 1 {
			return events, "invalid_type"
		}
		key, refusal := field(limits.KeyBytes, "key")
		if refusal != "" {
			return events, refusal
		}
		event := importEvent{Operation: "Delete", Key: hex.EncodeToString(key)}
		if kind == 1 {
			value, refusal := field(limits.ValueBytes, "value")
			if refusal != "" {
				return events, refusal
			}
			encoded := hex.EncodeToString(value)
			event.Operation, event.Value = "Put", &encoded
		}
		events = append(events, event)
	}
	return events, ""
}

type importStage struct {
	expected []importEvent
	events   []importEvent
	state    map[string]string
	refusal  string
	limits   importTargetLimits
	hexBytes uint64
}

func (s *importStage) event(event importEvent) {
	// Record at most the first mismatch beyond the selected bounded sequence.
	if s.refusal != "" {
		return
	}
	index := len(s.events)
	s.events = append(s.events, event)
	if index >= len(s.expected) {
		s.refusal = "callback_mismatch"
		return
	}
	wanted := s.expected[index]
	if event.Operation != wanted.Operation || event.Key != wanted.Key ||
		(event.Value == nil) != (wanted.Value == nil) ||
		(event.Value != nil && *event.Value != *wanted.Value) {
		s.refusal = "callback_mismatch"
		return
	}
	// Bound every transient map, not just its eventual final state. Account for
	// replacement and Delete before adding a Put, without mutating on refusal.
	entries, total := uint64(len(s.state)), s.hexBytes
	if old, exists := s.state[event.Key]; exists {
		entries--
		total -= uint64(len(event.Key)) + uint64(len(old))
	}
	if event.Value != nil {
		if entries >= s.limits.Entries {
			s.refusal = "target_entry_limit"
			return
		}
		for _, part := range []string{event.Key, *event.Value} {
			if uint64(len(part)) > s.limits.HexBytes-total {
				s.refusal = "target_hex_limit"
				return
			}
			total += uint64(len(part))
		}
	}
	s.hexBytes = total
	if event.Value == nil {
		delete(s.state, event.Key)
	} else {
		s.state[event.Key] = *event.Value
	}
}

// Compare every callback byte before sharing the preflight's detached immutable
// strings. Length and lowercase nibbles must match; no callback slice is retained.
func importHexMatches(encoded string, raw []byte) bool {
	if len(encoded)%2 != 0 || len(encoded)/2 != len(raw) {
		return false
	}
	const digits = "0123456789abcdef"
	for i, value := range raw {
		if encoded[2*i] != digits[value>>4] || encoded[2*i+1] != digits[value&15] {
			return false
		}
	}
	return true
}

func (s *importStage) Put(key, value []byte) {
	if s.refusal != "" {
		return
	}
	if index := len(s.events); index < len(s.expected) {
		wanted := s.expected[index]
		if wanted.Operation == "Put" && wanted.Value != nil &&
			importHexMatches(wanted.Key, key) && importHexMatches(*wanted.Value, value) {
			// Share the immutable string payload, not the mutable Value pointer.
			encoded := *wanted.Value
			s.event(importEvent{"Put", wanted.Key, &encoded})
			return
		}
	}
	// The first mismatch records the actual callback, including empty Put values.
	encoded := hex.EncodeToString(value)
	s.event(importEvent{"Put", hex.EncodeToString(key), &encoded})
}
func (s *importStage) Delete(key []byte) {
	if s.refusal != "" {
		return
	}
	if index := len(s.events); index < len(s.expected) {
		wanted := s.expected[index]
		if wanted.Operation == "Delete" && wanted.Value == nil && importHexMatches(wanted.Key, key) {
			s.event(importEvent{"Delete", wanted.Key, nil})
			return
		}
	}
	s.event(importEvent{"Delete", hex.EncodeToString(key), nil})
}

type importReplayFault struct {
	db.Patch
	fault string
}

type importFaultReceiver struct {
	db.PatchReplayer
	fault string
	calls int
}

func (r *importFaultReceiver) deliver(key, value []byte, put bool) {
	r.calls++
	if (r.fault == "replay-error-first" && r.calls > 1) || (r.fault == "replay-omit-last" && r.calls == 3) {
		return
	}
	if r.fault == "replay-wrong-value" && r.calls == 1 {
		value = append([]byte{}, value...)
		value[len(value)-1] ^= 1
	}
	if put {
		r.PatchReplayer.Put(key, value)
	} else {
		r.PatchReplayer.Delete(key)
	}
}

func (r *importFaultReceiver) Put(key, value []byte) { r.deliver(key, value, true) }
func (r *importFaultReceiver) Delete(key []byte)     { r.deliver(key, nil, false) }

func (p importReplayFault) Replay(target db.PatchReplayer) error {
	err := p.Patch.Replay(&importFaultReceiver{PatchReplayer: target, fault: p.fault})
	if err != nil {
		return err
	}
	if p.fault == "replay-extra" {
		target.Put(decodeKey(8), decodeValue(9))
	}
	if p.fault == "replay-error-first" || p.fault == "replay-error-complete" {
		return errors.New("injected research replay error")
	}
	return nil
}

func importInitial() map[string]string {
	return map[string]string{hex.EncodeToString(decodeKey(1)): hex.EncodeToString(decodeValue(5)),
		hex.EncodeToString(decodeKey(2)):  hex.EncodeToString(decodeValue(7)),
		hex.EncodeToString(decodeKey(99)): hex.EncodeToString(decodeValue(123))}
}

type importExecution struct {
	stage            *importStage
	target           map[string]string
	constructorCalls int
	replayCalls      int
	replacements     int
	rawCopies        int
	cloneCalls       int
	clonedEntries    int
	refusal          string
}

// Both fixture modes use this contract. Constructor/replay fault injection is
// confined to this research harness; no callback ever sees the original map.
func importApply(input importInput, target map[string]string, limits importTargetLimits) importExecution {
	stage := &importStage{expected: []importEvent{}, events: []importEvent{}, limits: limits}
	result := importExecution{stage: stage, target: target}
	apply := func() string {
		if !importBounds(input.limits) {
			return "invalid_limits"
		}
		if uint64(len(input.raw)) > input.limits.RawBytes {
			return "raw_limit"
		}
		total, reason := importTargetPreflight(target, limits)
		if reason != "" {
			return reason
		}
		// Copy only after the raw cap. Planning and candidate Load share no bytes
		// with the caller's source; event keys/values are detached strings.
		owned := append([]byte{}, input.raw...)
		result.rawCopies++
		stage.expected, reason = importPreflight(owned, input.limits)
		if reason != "" {
			return reason
		}
		matches := func() bool {
			return uint64(len(owned)) == input.selection.Bytes && uint64(len(stage.expected)) == input.selection.Records &&
				types.NewHash(owned).String() == input.selection.ChangesHash
		}
		if !matches() {
			return "selection_mismatch"
		}
		result.constructorCalls++
		patch, err := db.NewPatchFromDump(owned)
		if input.fault == "load-error" {
			err = errors.New("injected research constructor error with nonnil patch")
		}
		if input.fault == "load-nil" {
			patch = nil
		}
		if err != nil {
			return "load_error"
		}
		if patch == nil {
			return "nil_patch"
		}
		if input.fault == "mutate-source-after-load" {
			input.raw[len(input.raw)-1] ^= 1
		}
		if input.fault == "mutate-owned-after-load" {
			owned[len(owned)-1] ^= 1
		}
		if !matches() || !bytes.Equal(patch.Dump(), owned) {
			return "patch_bytes_mismatch"
		}
		if input.fault != "none" && input.fault != "mutate-source-after-load" {
			patch = importReplayFault{patch, input.fault}
		}
		// Clone only after complete input selection, constructor and dump checks.
		// The target cap was checked before raw copying; exclusive ownership must
		// continue through this clone, replay and the final pointer replacement.
		stage.state = make(map[string]string, len(target))
		for key, value := range target {
			stage.state[key] = value
			result.clonedEntries++
		}
		stage.hexBytes = total
		result.cloneCalls++
		result.replayCalls++
		if err = patch.Replay(stage); err != nil {
			return "replay_error"
		}
		if stage.refusal != "" {
			return stage.refusal
		}
		if len(stage.events) != len(stage.expected) {
			return "incomplete_replay"
		}
		if !matches() || !bytes.Equal(patch.Dump(), owned) {
			return "patch_bytes_mismatch"
		}
		// One map replacement after every check; no staged callback touched target.
		result.target = stage.state
		result.replacements++
		return ""
	}
	result.refusal = apply()
	return result
}

func importCase(input importInput) any {
	before := append([]byte{}, input.raw...)
	execution := importApply(input, importInitial(), importTargetCeilings)
	stage, refusal := execution.stage, execution.refusal
	result := "REJECTED"
	if refusal == "" {
		result = "STAGED"
	}
	return map[string]any{"name": input.name, "input": hex.EncodeToString(before), "source_after": hex.EncodeToString(input.raw),
		"limits": input.limits, "selection": input.selection, "injected_fault": input.fault,
		"preflight_records": len(stage.expected), "constructor_calls": execution.constructorCalls, "default_replay_calls": execution.replayCalls,
		"staging_callbacks": stage.events, "target_before": decodeManifest(importInitial()), "target_after": decodeManifest(execution.target),
		"target_replacements": execution.replacements, "research_import_result": result, "refusal": refusal, "consumer_result": "REFUSED"}
}

func generatePatchImport() any {
	cases := []any{}
	for _, input := range importInputs() {
		cases = append(cases, importCase(input))
	}
	return map[string]any{"format_version": 1, "kind": "candidate-patch-import-research",
		"source":         map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"limits_ceiling": importCeilings, "default_limits": importDefaults,
		"scope": map[string]bool{"synthetic": true, "unsigned": true, "bounded_research_preflight_executed": true,
			"actual_NewPatchFromDump_executed": true, "default_Batch_Replay_executed": true, "injected_constructor_and_replay_faults": true,
			"owned_memory_map_replacement_executed": true, "single_exclusive_caller": true,
			"decoder_panic_recovery_used": false, "node_database_opened": false, "actual_NodeTree_executed": false,
			"production_caller_execution": false, "production_corruption_reachability_qualified": false,
			"authenticated_snapshot_import": false, "shared_writer_atomicity": false, "crash_durability": false,
			"resource_measurements_executed": false, "network_execution": false, "full_node_started": false,
			"signing": false, "transactions": false, "profile_agreed": false, "network_activation_authenticated": false,
			"runtime_state_proof_acceptance": false}, "cases": cases}
}

func init() { patchImportGenerator = generatePatchImport }
