//go:build candidate_patch_file

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/zenon-network/go-zenon/common/types"
)

type fileInfoOverride struct {
	os.FileInfo
	size int64
}

func (f fileInfoOverride) Size() int64 { return f.size }

// Faults are explicit research controls around owned fixture files, not
// observations about remote corruption or a production filesystem writer.
type fileFaultSource struct {
	*os.File
	fault string
	stats int
}

func (f *fileFaultSource) Stat() (os.FileInfo, error) {
	f.stats++
	if f.fault == "stat-error" || (f.fault == "second-stat-error" && f.stats == 2) {
		return nil, errors.New("injected research stat error")
	}
	if f.fault == "nil-stat-info" {
		return nil, nil
	}
	info, err := f.File.Stat()
	if err == nil && f.fault == "negative-size" {
		return fileInfoOverride{info, -1}, nil
	}
	if err == nil && f.stats == 2 && (f.fault == "grow-after-read" || f.fault == "shrink-after-read") {
		if f.fault == "grow-after-read" {
			_, err = f.WriteAt([]byte{2}, info.Size())
		} else {
			err = f.Truncate(info.Size() - 1)
		}
		if err != nil {
			panic(err)
		}
		return f.File.Stat()
	}
	return info, err
}

func (f *fileFaultSource) ReadAt(buffer []byte, offset int64) (int, error) {
	if f.fault == "read-error" {
		n, _ := f.File.ReadAt(buffer[:1], offset)
		return n, errors.New("injected research read error")
	}
	if f.fault == "negative-read-count" {
		return -1, nil
	}
	if f.fault == "excess-read-count" {
		return len(buffer) + 1, nil
	}
	if f.fault == "short-eof-read" {
		n, _ := f.File.ReadAt(buffer[:1], offset)
		return n, io.EOF
	}
	info, err := f.File.Stat()
	if err != nil {
		panic(err)
	}
	switch f.fault {
	case "grow-before-read":
		_, err = f.WriteAt([]byte{2}, info.Size())
	case "shrink-before-read":
		err = f.Truncate(info.Size() - 1)
	case "same-size-mutation":
		_, err = f.WriteAt([]byte{90}, 66)
	}
	if err != nil {
		panic(err)
	}
	return f.File.ReadAt(buffer, offset)
}

type fileCaseInput struct {
	targetInput
	sourceFault string
}

func fileInputs() []fileCaseInput {
	rows := []fileCaseInput{}
	for _, input := range targetInputs() {
		rows = append(rows, fileCaseInput{input, "none"})
	}
	base := targetInputs()[0]
	for _, fault := range []string{"nil-source", "closed-source", "directory-source", "stat-error", "nil-stat-info", "negative-size",
		"second-stat-error", "read-error", "negative-read-count", "excess-read-count", "short-eof-read", "grow-before-read",
		"shrink-before-read", "grow-after-read", "shrink-after-read", "same-size-mutation"} {
		row := base
		row.name = "source-" + fault
		rows = append(rows, fileCaseInput{row, fault})
	}
	for _, fault := range []string{"wrong-byte-count", "wrong-record-count", "selection-over-cap", "selection-uint64-max", "file-over-cap"} {
		row := base
		row.name = fault
		switch fault {
		case "wrong-byte-count":
			row.input.selection.Bytes--
		case "wrong-record-count":
			row.input.selection.Records--
		case "selection-over-cap":
			row.input.selection.Bytes = row.input.limits.RawBytes + 1
		case "selection-uint64-max":
			row.input.selection.Bytes = ^uint64(0)
		case "file-over-cap":
			row.input.raw = bytes.Repeat([]byte{0}, int(importCeilings.RawBytes)+1)
		}
		rows = append(rows, fileCaseInput{row, "none"})
	}
	return rows
}

func fileDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func fileCase(t *testing.T, row fileCaseInput) any {
	t.Helper()
	root := t.TempDir()
	name := filepath.Join(root, "owned-dump.bin")
	raw := append([]byte{}, row.input.raw...)
	if err := os.WriteFile(name, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	if _, err = file.Seek(3, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	var source importFileSource = &fileFaultSource{File: file, fault: row.sourceFault}
	cursorAvailable := true
	switch row.sourceFault {
	case "nil-source":
		source, cursorAvailable = nil, false
	case "closed-source":
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
		cursorAvailable = false
	case "directory-source":
		directory, openErr := os.Open(root)
		if openErr != nil {
			t.Fatal(openErr)
		}
		defer directory.Close()
		source, cursorAvailable = directory, false
	}
	input := row.input
	input.raw = nil // No caller raw slice is an input to the file handoff.
	before := targetSummary(row.target)
	execution := importFileApply(source, input, row.target, row.limits)
	afterBytes, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(targetSummary(row.target), before) {
		t.Fatal("original alias changed")
	}
	if execution.refusal != "" && reflect.ValueOf(execution.target).Pointer() != reflect.ValueOf(row.target).Pointer() {
		t.Fatal("refusal replaced original map")
	}
	if cursorAvailable {
		position, seekErr := file.Seek(0, io.SeekCurrent)
		if seekErr != nil || position != 3 {
			t.Fatal("borrowed descriptor cursor changed or descriptor closed")
		}
	}
	result := "STAGED"
	if execution.refusal != "" {
		result = "REJECTED"
	}
	return map[string]any{"name": row.name, "source_fault": row.sourceFault, "import_fault": row.input.fault,
		"limits": row.input.limits, "selection": row.input.selection, "target_limits": row.limits,
		"file_before_bytes": len(raw), "file_before_sha256": fileDigest(raw),
		"file_after_bytes": len(afterBytes), "file_after_sha256": fileDigest(afterBytes),
		"file_stat_calls": execution.statCalls, "file_read_calls": execution.readCalls,
		"file_buffer_bytes": execution.bufferBytes, "file_read_bytes": execution.readBytes,
		"source_cursor_available": cursorAvailable, "source_cursor_preserved": cursorAvailable,
		"raw_copies": execution.rawCopies, "constructor_calls": execution.constructorCalls,
		"target_clone_calls": execution.cloneCalls, "target_cloned_entries": execution.clonedEntries,
		"default_replay_calls": execution.replayCalls, "preflight_records": len(execution.stage.expected),
		"staging_callbacks": execution.stage.events, "target_before": before,
		"original_alias_after": targetSummary(row.target), "staging_target": targetSummary(execution.stage.state),
		"target_after": targetSummary(execution.target), "target_replacements": execution.replacements,
		"research_import_result": result, "refusal": execution.refusal, "consumer_result": "REFUSED"}
}

func TestFileHandoffReferenceCorpus(t *testing.T) {
	var pins map[string]string
	if err := json.Unmarshal([]byte(os.Getenv("FILE_HANDOFF_INPUT_PINS")), &pins); err != nil || len(pins) == 0 {
		t.Fatal("use the offline reproduce_patch_file.py source-validation driver")
	}
	cases := []any{}
	for _, row := range fileInputs() {
		cases = append(cases, fileCase(t, row))
	}
	scope := map[string]bool{}
	for _, name := range []string{"synthetic", "unsigned", "owned_temporary_regular_files", "opened_file_descriptor_handoff",
		"positional_read_at_zero", "selected_count_plus_one_read_bound", "actual_NewPatchFromDump_executed",
		"default_Batch_Replay_executed", "source_and_replay_faults_injected", "complete_map_and_original_alias_bindings", "single_exclusive_caller"} {
		scope[name] = true
	}
	for _, name := range []string{"path_opener_added", "atomic_filesystem_snapshot", "shared_writer_atomicity", "crash_durability",
		"authenticated_snapshot_import", "actual_NodeTree_executed", "node_database_opened", "resource_measurements_executed",
		"network_execution", "full_node_started", "signing", "transactions", "profile_agreed", "network_activation_authenticated",
		"execution_provenance_authenticated", "runtime_state_proof_acceptance"} {
		scope[name] = false
	}
	document := map[string]any{"format_version": 1, "kind": "candidate-patch-file-handoff-research",
		"source":                 map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"research_source_inputs": pins, "scope": scope, "cases": cases}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("PATCH_FILE_CORPUS=%s\n", raw)
}

func TestFileHandoffBorrowedReadOnlyDescriptor(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "selected.bin")
	raw := importSelectedDump("complete")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = file.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	target := importInitial()
	input := importInput{decodeInput{name: "read-only-descriptor"}, importDefaults, importSelect("complete"), "none"}
	execution := importFileApply(file, input, target, importTargetCeilings)
	if execution.refusal != "" || execution.replacements != 1 || !reflect.DeepEqual(targetSummary(target), targetSummary(importInitial())) {
		t.Fatal("selected read-only handoff failed or changed original alias")
	}
	if position, err := file.Seek(0, io.SeekCurrent); err != nil || position != 7 {
		t.Fatal("borrowed read-only cursor or lifetime changed")
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, after) {
		t.Fatal("source file changed")
	}
}

func TestFileHandoffRawCeiling(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ceiling.bin")
	raw := []byte{}
	for i := 0; i < 16; i++ {
		length := 65536
		if i == 15 {
			length = 65456
		}
		raw = append(raw, 1, 0)
		raw = append(raw, decodeVarint(uint64(length))...)
		raw = append(raw, make([]byte, length)...)
	}
	if len(raw) != 1<<20 {
		t.Fatal("literal raw ceiling fixture differs")
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	target := importInitial()
	input := importInput{decodeInput{name: "raw-ceiling"}, importCeilings,
		importSelection{"raw-ceiling", 1 << 20, 16, types.NewHash(raw).String()}, "none"}
	execution := importFileApply(file, input, target, importTargetCeilings)
	if execution.refusal != "" || execution.replacements != 1 || execution.bufferBytes != (1<<20)+1 ||
		execution.readBytes != 1<<20 || len(execution.stage.events) != 16 || execution.target[""] != hex.EncodeToString(make([]byte, 65456)) {
		t.Fatal("raw ceiling handoff or final repeated-key value differs")
	}
	if !reflect.DeepEqual(targetSummary(target), targetSummary(importInitial())) {
		t.Fatal("raw ceiling changed original alias")
	}
	if err := os.WriteFile(path, append(raw, 2), 0o600); err != nil {
		t.Fatal(err)
	}
	execution = importFileApply(file, input, target, importTargetCeilings)
	if execution.refusal != "file_size_limit" || execution.bufferBytes != 0 || execution.readCalls != 0 || execution.rawCopies != 0 {
		t.Fatal("oversize file was read or copied")
	}
}
