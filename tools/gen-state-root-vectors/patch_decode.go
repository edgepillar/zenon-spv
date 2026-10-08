//go:build candidate_patch_decode || candidate_patch_import

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/zenon-network/go-zenon/common/db"
)

type decodeInput struct {
	name string
	raw  []byte
}

func decodeKey(index uint32) []byte {
	key := append([]byte{3}, bytes.Repeat([]byte{0x11}, 20)...)
	binary.BigEndian.PutUint32(key[17:], index)
	return append(append(key, 3), bytes.Repeat([]byte{0x22}, 10)...)
}

func decodeValue(amount uint64) []byte {
	value := make([]byte, 32)
	binary.BigEndian.PutUint64(value[24:], amount)
	return value
}

func decodeComplete() db.Patch {
	patch := db.NewPatch()
	patch.Put(decodeKey(1), decodeValue(91))
	patch.Delete(decodeKey(2))
	patch.Put(decodeKey(8), decodeValue(9))
	return patch
}

func decodeVarint(value uint64) []byte {
	var data [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(data[:], value)
	return append([]byte{}, data[:n]...)
}

func decodeInputs() []decodeInput {
	complete := append([]byte{}, decodeComplete().Dump()...)
	inputs := []decodeInput{}
	for cut := 0; cut <= len(complete); cut++ {
		inputs = append(inputs, decodeInput{fmt.Sprintf("prefix-%03d", cut), append([]byte{}, complete[:cut]...)})
	}
	tails := []decodeInput{
		{"type-02", []byte{2}}, {"type-ff", []byte{0xff}},
		{"key-truncated-varint", []byte{0, 0x80}},
		{"key-overflow-varint", append(append([]byte{0}, bytes.Repeat([]byte{0xff}, 9)...), 2)},
		{"key-ten-continuations", append([]byte{0}, bytes.Repeat([]byte{0x80}, 10)...)},
		{"key-eleven-continuations", append([]byte{0}, bytes.Repeat([]byte{0x80}, 11)...)},
		{"key-short-bytes", []byte{0, 2, 0}},
		{"value-truncated-varint", []byte{1, 0, 0x80}},
		{"value-overflow-varint", append(append([]byte{1, 0}, bytes.Repeat([]byte{0xff}, 9)...), 2)},
		{"value-short-bytes", []byte{1, 0, 2, 0}},
	}
	for _, value := range []uint64{1<<63 - 1, 1 << 63, 1<<64 - 1} {
		length := decodeVarint(value)
		tails = append(tails,
			decodeInput{fmt.Sprintf("delete-key-length-%d", value), append([]byte{0}, length...)},
			decodeInput{fmt.Sprintf("put-key-length-%d", value), append([]byte{1}, length...)},
			decodeInput{fmt.Sprintf("put-value-length-%d", value), append([]byte{1, 0}, length...)})
	}
	first := decodeComplete().Dump()[:67]
	for _, prefix := range []decodeInput{{"fresh", nil}, {"after-one", first}, {"after-complete", complete}} {
		for _, tail := range tails {
			raw := append(append([]byte{}, prefix.raw...), tail.raw...)
			inputs = append(inputs, decodeInput{prefix.name + "/" + tail.name, raw})
		}
	}
	inputs = append(inputs,
		decodeInput{"valid-empty-delete", []byte{0, 0}},
		decodeInput{"valid-empty-put", []byte{1, 0, 0}},
		decodeInput{"valid-overlong-empty-put", []byte{1, 0x80, 0, 0x80, 0}})
	// The decoder accepts a redundant varint representation. The equivalent
	// callbacks do not give the raw dump the same ChangesHash.
	overlong := append([]byte{1, 0xa0, 0}, decodeKey(1)...)
	overlong = append(overlong, 0xa0, 0)
	overlong = append(overlong, decodeValue(91)...)
	overlong = append(overlong, complete[67:]...)
	inputs = append(inputs, decodeInput{"valid-overlong-complete", overlong})
	for _, amount := range []uint64{9, 10} {
		tail := db.NewPatch()
		tail.Put(decodeKey(8), decodeValue(amount))
		inputs = append(inputs, decodeInput{fmt.Sprintf("valid-duplicate-put-%d", amount), append(append([]byte{}, complete...), tail.Dump()...)})
	}
	return inputs
}

type decodeRecorder struct {
	events []any
	state  map[string]string
}

func (r *decodeRecorder) Put(key, value []byte) {
	k, v := hex.EncodeToString(key), hex.EncodeToString(value)
	r.events = append(r.events, map[string]any{"operation": "Put", "key": k, "value": v})
	r.state[k] = v
}

func (r *decodeRecorder) Delete(key []byte) {
	k := hex.EncodeToString(key)
	r.events = append(r.events, map[string]any{"operation": "Delete", "key": k, "value": nil})
	delete(r.state, k)
}

func decodeManifest(state map[string]string) []any {
	keys := []string{}
	for key := range state {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rows := []any{}
	for _, key := range keys {
		rows = append(rows, map[string]any{"key": key, "value": state[key]})
	}
	return rows
}

func decodePanic(value any) any {
	if value == nil {
		return nil
	}
	err, ok := value.(runtime.Error)
	require(ok, "unexpected non-runtime decoder panic")
	message := err.Error()
	require(strings.HasPrefix(message, "runtime error: slice bounds out of range") || strings.HasPrefix(message, "runtime error: index out of range"), "unexpected runtime decoder panic")
	return "runtime_bounds"
}

func decodeLoad(raw []byte) (patch db.Patch, err error, panicResult any) {
	defer func() { panicResult = decodePanic(recover()) }()
	patch, err = db.NewPatchFromDump(raw)
	return
}

func decodeReplay(patch db.Patch, target *decodeRecorder) (err error, panicResult any) {
	defer func() { panicResult = decodePanic(recover()) }()
	err = patch.Replay(target)
	return
}

func decodeError(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}

func decodeCase(input decodeInput) any {
	patch, loadErr, loadPanic := decodeLoad(input.raw)
	recorder := &decodeRecorder{events: []any{}, state: map[string]string{}}
	var replayErr error
	var replayPanic, dump, hash, indexed any
	if patch != nil {
		// Deliberately replay even an error-returned patch only in this diagnostic
		// fixture. A real caller must discard it when NewPatchFromDump fails.
		replayErr, replayPanic = decodeReplay(patch, recorder)
		dump, hash = hex.EncodeToString(patch.Dump()), db.PatchHash(patch).String()
		indexed = patch.(interface{ Len() int }).Len()
	}
	selected := map[string]string{hex.EncodeToString(decodeKey(1)): hex.EncodeToString(decodeValue(91)), hex.EncodeToString(decodeKey(8)): hex.EncodeToString(decodeValue(9))}
	matches := len(recorder.state) == len(selected)
	for key, value := range selected {
		matches = matches && recorder.state[key] == value
	}
	return map[string]any{"name": input.name, "input": hex.EncodeToString(input.raw),
		"load_error": decodeError(loadErr), "load_panic": loadPanic, "patch_returned": patch != nil,
		"indexed_records": indexed, "dump": dump, "patch_hash": hash,
		"diagnostic_replay_after_decode_error": patch != nil && loadErr != nil,
		"replay_error":                         decodeError(replayErr), "replay_panic": replayPanic,
		"replay_callbacks": recorder.events, "diagnostic_manifest": decodeManifest(recorder.state),
		"diagnostic_state_matches_selected_fixture": matches, "consumer_result": "REFUSED"}
}

func generatePatchDecode() any {
	require(strconv.IntSize == 64, "patch decode reference requires a 64-bit target")
	cases := []any{}
	for _, input := range decodeInputs() {
		cases = append(cases, decodeCase(input))
	}
	return map[string]any{"format_version": 1, "kind": "candidate-patch-decode-research",
		"source":     map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"dependency": map[string]string{"module": "github.com/syndtr/goleveldb", "version": "v1.0.1-0.20210819022825-2ae1ddf74ef7", "sum": "h1:epCh84lMvA70Z7CTTCmYQn2CKbY8j86K7/FAIr141uY=", "batch_source_sha256": "299129fbb88354f140bd7e7c83ffda6554e9af906ab68589f72e7c212f49c096"},
		"scope": map[string]bool{"synthetic": true, "unsigned": true, "reference_64_bit_integers": true,
			"actual_NewPatchFromDump_executed": true, "default_Batch_Replay_executed": true,
			"diagnostic_replay_after_decode_errors_executed": true, "runtime_bounds_panics_recovered_in_research": true,
			"custom_Patch_Replay_errors_injected": false, "node_database_opened": false, "actual_NodeTree_executed": false,
			"production_caller_execution": false, "production_corruption_reachability_qualified": false,
			"resource_measurements_executed": false, "network_execution": false, "full_node_started": false,
			"chain_Start_executed": false, "signing": false, "transactions": false, "profile_agreed": false,
			"network_activation_authenticated": false, "runtime_state_proof_acceptance": false},
		"complete_dump":              hex.EncodeToString(decodeComplete().Dump()),
		"selected_complete_manifest": decodeManifest(map[string]string{hex.EncodeToString(decodeKey(1)): hex.EncodeToString(decodeValue(91)), hex.EncodeToString(decodeKey(8)): hex.EncodeToString(decodeValue(9))}),
		"cases":                      cases}
}

func init() { patchDecodeGenerator = generatePatchDecode }
