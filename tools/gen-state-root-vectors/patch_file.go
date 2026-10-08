//go:build candidate_patch_file

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"io"
	"os"
)

// The caller supplies an already opened, stable regular file and exclusively
// owns the target for the entire call. This private seam supports controlled
// I/O fault injection; real fixtures pass an *os.File. It does not open paths,
// acquire locks, publish files, authenticate selections or guarantee snapshots.
type importFileSource interface {
	Stat() (os.FileInfo, error)
	ReadAt([]byte, int64) (int, error)
}

type importFileExecution struct {
	importExecution
	statCalls, readCalls, bufferBytes, readBytes int
}

// Read from offset zero without changing the borrowed descriptor's cursor.
// Selection and payload caps are research policies, not process-memory budgets.
// Only the unchanged importApply contract may replace the returned owned map.
func importFileApply(source importFileSource, input importInput, target map[string]string, limits importTargetLimits) importFileExecution {
	result := importFileExecution{importExecution: importExecution{
		stage: &importStage{expected: []importEvent{}, events: []importEvent{}, limits: limits}, target: target}}
	refuse := func(reason string) importFileExecution {
		result.refusal = reason
		return result
	}
	if !importBounds(input.limits) {
		return refuse("invalid_limits")
	}
	if input.selection.Bytes > input.limits.RawBytes {
		return refuse("file_selection_limit")
	}
	if _, reason := importTargetPreflight(target, limits); reason != "" {
		return refuse(reason)
	}
	if source == nil {
		return refuse("file_stat_error")
	}
	result.statCalls++
	info, err := source.Stat()
	if err != nil || info == nil {
		return refuse("file_stat_error")
	}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return refuse("file_not_regular")
	}
	if uint64(info.Size()) > input.limits.RawBytes {
		return refuse("file_size_limit")
	}
	if uint64(info.Size()) != input.selection.Bytes {
		return refuse("file_selection_size")
	}
	// The extra byte detects growth visible during ReadAt. Conversion/addition
	// follows the positive, at-most-1-MiB raw cap; an unbounded count cannot allocate.
	buffer := make([]byte, int(input.selection.Bytes)+1)
	result.bufferBytes, result.readCalls = len(buffer), 1
	n, err := source.ReadAt(buffer, 0)
	if n < 0 || n > len(buffer) {
		return refuse("file_read_error")
	}
	result.readBytes = n
	if err != nil && err != io.EOF {
		return refuse("file_read_error")
	}
	if uint64(n) != input.selection.Bytes {
		return refuse("file_read_size")
	}
	result.statCalls++
	after, err := source.Stat()
	if err != nil || after == nil {
		return refuse("file_stat_error")
	}
	if !after.Mode().IsRegular() || after.Size() != info.Size() {
		return refuse("file_changed_size")
	}
	// Size observations do not establish an atomic filesystem snapshot. The
	// detached bytes must still pass raw parsing, byte/count/digest selection,
	// candidate Dump equality, ordered replay and initial/transient target caps.
	input.raw = buffer[:n]
	result.importExecution = importApply(input, target, limits)
	return result
}
