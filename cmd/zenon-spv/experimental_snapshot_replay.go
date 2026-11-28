// SPDX-License-Identifier: MIT

package main

import (
	"crypto/sha256"

	"github.com/0x3639/zenon-spv/internal/chain"
)

const replayedSnapshotProjectionFormat = "zenon-r1-ledger-churn-transport/v1"

type snapshotReplayComparison struct {
	Plan       snapshotBytePin `json:"plan"`
	Base       snapshotBytePin `json:"base"`
	BaseHeight uint64          `json:"base_height"`
	BaseHash   chain.Hash      `json:"base_hash"`
	Patch      snapshotBytePin `json:"patch"`
}

type snapshotReplayFrame struct {
	Pin     snapshotBytePin
	Records uint64
}

func (f *snapshotReplayFrame) fields() map[string]any {
	return map[string]any{"bytes": &f.Pin.Bytes, "sha256": &f.Pin.SHA256, "records": &f.Records}
}

func (f *snapshotReplayFrame) UnmarshalJSON(raw []byte) error {
	return decodeExperimentalCLIObject(raw, f.fields())
}

func (f snapshotReplayFrame) fits(maxBytes, maxRecords, minRecordBytes uint64) bool {
	return !f.Pin.SHA256.IsZero() && f.Pin.Bytes <= maxBytes && f.Records <= maxRecords &&
		(f.Pin.Bytes == 0) == (f.Records == 0) && f.Records <= f.Pin.Bytes/minRecordBytes
}

type snapshotReplayEndpoint struct {
	snapshotReplayFrame
	Height uint64
	Hash   chain.Hash
}

func (e *snapshotReplayEndpoint) UnmarshalJSON(raw []byte) error {
	var momentum experimentalCLIFieldSpan
	fields := e.fields()
	fields["momentum"] = &momentum
	if err := decodeExperimentalCLIObject(raw, fields); err != nil {
		return err
	}
	return decodeExperimentalCLIObject(momentum, map[string]any{"height": &e.Height, "hash": &e.Hash})
}

func decodeReplayedSnapshotProjection(raw []byte) (snapshotProjectionSelection, error) {
	var format, status string
	var planBytes, limits, transport, projection, scope, beforeTotals, afterTotals experimentalCLIFieldSpan
	var plan snapshotBytePin
	var readBytes, targetRead, targetWritten uint64
	var eof bool
	if decodeExperimentalCLIObject(raw, map[string]any{
		"format": &format, "status": &status, "selection": &planBytes, "plan": &plan, "limits": &limits,
		"before_totals": &beforeTotals, "after_totals": &afterTotals,
		"operations": new(experimentalCLIFieldSpan), "families": new(experimentalCLIFieldSpan),
		"input_bytes": &readBytes, "after_snapshot_bytes_read": &targetRead,
		"derived_snapshot_bytes_written": &targetWritten, "end_of_stream_observed": &eof,
		"scope": &scope, "candidate_projection": &projection, "after_transport": &transport,
	}) != nil || format != replayedSnapshotProjectionFormat ||
		status != "SELECTED_PATCH_REPLAY_TRANSPORT_AND_PROJECTION_MATCHED" || !eof ||
		targetRead != 0 || targetWritten != 0 || plan.Bytes == 0 || plan.Bytes > 8<<10 ||
		plan.SHA256.IsZero() || uint64(len(planBytes))+1 != plan.Bytes {
		return snapshotProjectionSelection{}, errExperimentalCLIInput
	}
	// The replay embeds the exact canonical plan object. The original plan frame
	// was this encoding followed by one newline.
	digest := sha256.New()
	digest.Write(planBytes)
	digest.Write([]byte{'\n'})
	if chain.Hash(digest.Sum(nil)) != plan.SHA256 || !matchesSnapshotReportScope(scope, map[string]string{
		"record_space_declared": `"effective-raw-ledger"`,
		"classification":        `"candidate-prefix-layout-not-a-protocol-decision"`,
	}, "absence_or_delete_proof", "complete_ordered_patch_authenticated", "header_authentication_executed",
		"ledger_consistency_authenticated", "momentum_parent_link_authenticated", "network_activation_authenticated",
		"profile_agreed", "representative_dataset_accepted", "snapshot_completeness_authenticated",
		"state_value_acceptance_enabled") {
		return snapshotProjectionSelection{}, errExperimentalCLIInput
	}

	var maxBytes, maxRecords, maxKey, maxValue, maxPatchBytes, maxPatchRecords uint64
	if decodeExperimentalCLIObject(limits, map[string]any{
		"bytes": &maxBytes, "records": &maxRecords, "key_bytes": &maxKey, "value_bytes": &maxValue,
		"patch_bytes": &maxPatchBytes, "patch_records": &maxPatchRecords,
	}) != nil || maxBytes == 0 || maxBytes > 16<<30 || maxRecords == 0 || maxRecords > 100000000 ||
		maxKey == 0 || maxKey > 1<<20 || maxValue == 0 || maxValue > 64<<20 ||
		maxPatchBytes == 0 || maxPatchBytes > 64<<20 || maxPatchRecords == 0 || maxPatchRecords > 262144 {
		return snapshotProjectionSelection{}, errExperimentalCLIInput
	}

	var planFormat, space string
	var before, after snapshotReplayEndpoint
	var patch snapshotReplayFrame
	var provenance chain.Hash
	if decodeExperimentalCLIObject(planBytes, map[string]any{
		"format": &planFormat, "record_space": &space, "provenance_sha256": &provenance,
		"before": &before, "after": &after, "patch": &patch,
	}) != nil || planFormat != "zenon-r1-ledger-churn-plan/v1" || space != "effective-raw-ledger" || provenance.IsZero() ||
		before.Height == 0 || after.Height == 0 || before.Height != after.Height-1 ||
		before.Hash.IsZero() || after.Hash.IsZero() || before.Hash == after.Hash ||
		!before.fits(maxBytes, maxRecords, 3) || !after.fits(maxBytes, maxRecords, 3) || after.Records == 0 ||
		!patch.fits(maxPatchBytes, maxPatchRecords, 2) ||
		!matchesSnapshotReplayTotals(beforeTotals, before.snapshotReplayFrame) ||
		!matchesSnapshotReplayTotals(afterTotals, after.snapshotReplayFrame) {
		return snapshotProjectionSelection{}, errExperimentalCLIInput
	}

	selected := snapshotProjectionSelection{Height: after.Height, Hash: after.Hash}
	out := &selected.Comparison
	out.Stream, out.ProvenanceSHA256 = after.Pin, provenance
	if checkSnapshotReplayTransport(transport, &selected, maxBytes) != nil ||
		readBytes != plan.Bytes+out.Manifest.Bytes+patch.Pin.Bytes+before.Pin.Bytes ||
		checkSnapshotProjectionRoot(projection, after.Records, &selected) != nil {
		return snapshotProjectionSelection{}, errExperimentalCLIInput
	}
	out.Replay = &snapshotReplayComparison{
		Plan: plan, Base: before.Pin, BaseHeight: before.Height, BaseHash: before.Hash, Patch: patch.Pin,
	}
	return selected, nil
}

func matchesSnapshotReplayTotals(raw []byte, frame snapshotReplayFrame) bool {
	var records, keys, values, wire uint64
	return decodeExperimentalCLIObject(raw, map[string]any{
		"records": &records, "key_bytes": &keys, "raw_value_bytes": &values, "put_wire_bytes": &wire,
	}) == nil && records == frame.Records && wire == frame.Pin.Bytes &&
		keys <= wire && values <= wire-keys && records <= (wire-keys-values)/3
}

func checkSnapshotReplayTransport(raw []byte, selected *snapshotProjectionSelection, maxBytes uint64) error {
	var format, status, space string
	var count, height, transportBytes, maxChunkBytes, maxChunks uint64
	var complete bool
	var target, scope, limits experimentalCLIFieldSpan
	out := &selected.Comparison
	if decodeExperimentalCLIObject(raw, map[string]any{
		"format": &format, "status": &status, "manifest": &out.Manifest, "selection": &target,
		"chunks_checked": &count, "emitted_stream_completed": &complete, "limits": &limits, "scope": &scope,
	}) != nil || format != "zenon-r1-transport-emitted-check/v1" ||
		status != "SELECTED_EMITTED_TRANSPORT_MATCHED" || !complete ||
		out.Manifest.Bytes == 0 || out.Manifest.Bytes > 512<<10 || out.Manifest.SHA256.IsZero() ||
		decodeExperimentalCLIObject(limits, map[string]any{
			"bytes": &transportBytes, "chunk_bytes": &maxChunkBytes, "chunks": &maxChunks,
		}) != nil || transportBytes != maxBytes || maxChunkBytes != 64<<20 || maxChunks != 4096 ||
		count == 0 || count > maxChunks || count > out.Stream.Bytes || count*maxChunkBytes < out.Stream.Bytes ||
		!matchesSnapshotReportScope(scope, nil, "header_authentication_executed", "ledger_consistency_authenticated",
			"ledger_origin_authenticated", "ledger_record_syntax_checked", "network_activation_authenticated",
			"profile_agreed", "representative_dataset_accepted", "snapshot_completeness_authenticated",
			"state_tree_reconstructed", "state_value_acceptance_enabled") {
		return errExperimentalCLIInput
	}

	var stream snapshotBytePin
	var hash, provenance chain.Hash
	if decodeExperimentalCLIObject(target, map[string]any{
		"height": &height, "hash": &hash, "record_space": &space, "provenance_sha256": &provenance,
		"bytes": &stream.Bytes, "sha256": &stream.SHA256,
	}) != nil || height != selected.Height || hash != selected.Hash || space != "effective-raw-ledger" ||
		provenance != out.ProvenanceSHA256 || stream != out.Stream {
		return errExperimentalCLIInput
	}
	return nil
}

func matchesSnapshotReportScope(raw []byte, literals map[string]string, flags ...string) bool {
	fields := make(map[string]any, len(literals)+len(flags))
	for name := range literals {
		fields[name] = new(experimentalCLIFieldSpan)
	}
	for _, name := range flags {
		fields[name] = new(experimentalCLIFieldSpan)
	}
	if decodeExperimentalCLIObject(raw, fields) != nil {
		return false
	}
	for name, literal := range literals {
		if string(*fields[name].(*experimentalCLIFieldSpan)) != literal {
			return false
		}
	}
	for _, name := range flags {
		if string(*fields[name].(*experimentalCLIFieldSpan)) != "false" {
			return false
		}
	}
	return true
}
