// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"

	"github.com/0x3639/zenon-spv/internal/chain"
)

const maxSnapshotProjectionReportBytes = 148 << 10
const experimentalSnapshotProjectionProfile = "zenon-l1-balance-storage-sha3/v1"

type snapshotBytePin struct {
	Bytes  uint64     `json:"bytes"`
	SHA256 chain.Hash `json:"sha256"`
}

func (p *snapshotBytePin) UnmarshalJSON(raw []byte) error {
	return decodeExperimentalCLIObject(raw, map[string]any{"bytes": &p.Bytes, "sha256": &p.SHA256})
}

type experimentalProjectionComparison struct {
	ReportSHA256          chain.Hash      `json:"report_sha256"`
	Profile               string          `json:"profile"`
	Manifest              snapshotBytePin `json:"manifest"`
	Stream                snapshotBytePin `json:"stream"`
	ProvenanceSHA256      chain.Hash      `json:"provenance_sha256"`
	ProducerReceiptSHA256 chain.Hash      `json:"producer_receipt_sha256"`
}

type snapshotProjectionSelection struct {
	Height     uint64
	Hash       chain.Hash
	Root       chain.Hash
	Comparison experimentalProjectionComparison
}

type snapshotInventorySelection struct {
	Stream     snapshotBytePin
	Records    uint64
	Provenance chain.Hash
	Space      string
}

func (s *snapshotInventorySelection) UnmarshalJSON(raw []byte) error {
	return decodeExperimentalCLIObject(raw, map[string]any{
		"bytes": &s.Stream.Bytes, "sha256": &s.Stream.SHA256, "records": &s.Records,
		"provenance_sha256": &s.Provenance, "record_space": &s.Space,
	})
}

// Decode only the fixed S1 report. The selected digest identifies the report
// bytes, and the independently verified header supplies the comparison root.
// This decoder does not read or attest to the underlying projection input.
func decodeSnapshotProjectionReport(raw []byte) (snapshotProjectionSelection, error) {
	var selected snapshotProjectionSelection
	var format, status string
	var completionMatched, inventoryComplete bool
	var completion, inventory, transport, projection, reason json.RawMessage
	var scope map[string]bool
	if len(raw) > maxSnapshotProjectionReportBytes || decodeExperimentalCLIObject(raw, map[string]any{
		"format": &format, "status": &status, "reason": &reason, "scope": &scope,
		"producer_completion_matched": &completionMatched, "stream_recount_completed": &inventoryComplete,
		"producer_completion": &completion, "stream_inventory": &inventory,
		"transport_verification": &transport, "candidate_projection": &projection,
	}, "reason") != nil || format != "zenon-completed-frontier-transport-projection/v1" ||
		status != "SELECTED_CANDIDATE_PROJECTION_MATCHED" || !bytes.Equal(reason, []byte("null")) ||
		!completionMatched || !inventoryComplete || len(scope) == 0 {
		return selected, errExperimentalCLIInput
	}
	for _, claim := range scope {
		if claim {
			return selected, errExperimentalCLIInput
		}
	}

	out := &selected.Comparison
	var transportFormat, transportStatus, space string
	var streamEOF bool
	var chunks, readLimit uint64
	var transportSelection, transportReason json.RawMessage
	if decodeExperimentalCLIObject(transport, map[string]any{
		"format": &transportFormat, "status": &transportStatus, "reason": &transportReason,
		"manifest": &out.Manifest, "selection": &transportSelection,
		"chunks_checked": &chunks, "stream_eof_observed": &streamEOF, "read_request_limit_bytes": &readLimit,
		"limits": new(json.RawMessage), "scope": new(json.RawMessage),
	}, "reason") != nil || transportFormat != "zenon-r1-transport-check/v1" ||
		transportStatus != "SELECTED_TRANSPORT_MATCHED" || !bytes.Equal(transportReason, []byte("null")) ||
		!streamEOF || chunks == 0 || chunks > 4096 || readLimit != 64<<10 ||
		out.Manifest.Bytes == 0 || out.Manifest.Bytes > 512<<10 || out.Manifest.SHA256.IsZero() {
		return snapshotProjectionSelection{}, errExperimentalCLIInput
	}
	if decodeExperimentalCLIObject(transportSelection, map[string]any{
		"height": &selected.Height, "hash": &selected.Hash, "provenance_sha256": &out.ProvenanceSHA256,
		"bytes": &out.Stream.Bytes, "sha256": &out.Stream.SHA256, "record_space": &space,
	}) != nil || space != "effective-raw-ledger" || selected.Height == 0 || selected.Hash.IsZero() ||
		out.ProvenanceSHA256.IsZero() || out.Stream.SHA256.IsZero() || out.Stream.Bytes == 0 || out.Stream.Bytes > 16<<30 {
		return snapshotProjectionSelection{}, errExperimentalCLIInput
	}
	records, err := checkSnapshotProjectionInputs(completion, inventory, &selected)
	if err != nil || checkSnapshotProjectionRoot(projection, records, &selected) != nil {
		return snapshotProjectionSelection{}, errExperimentalCLIInput
	}
	return selected, nil
}

func checkSnapshotProjectionInputs(completion, inventory []byte, selected *snapshotProjectionSelection) (uint64, error) {
	var format, status string
	var captureMatched bool
	var frontier, reason json.RawMessage
	var captured snapshotInventorySelection
	out := &selected.Comparison
	if decodeExperimentalCLIObject(completion, map[string]any{
		"format": &format, "status": &status, "reason": &reason, "capture_matched": &captureMatched,
		"selected_frontier": &frontier, "inventory_selection": &captured,
		"producer_receipt_sha256": &out.ProducerReceiptSHA256, "inventory_limits": new(json.RawMessage),
		"statistics_origin": new(json.RawMessage), "scope": new(json.RawMessage),
	}, "reason") != nil || format != "zenon-frontier-export-completion/v1" ||
		status != "SELECTED_EXPORT_COMPLETION_MATCHED" || !bytes.Equal(reason, []byte("null")) ||
		!captureMatched || out.ProducerReceiptSHA256.IsZero() {
		return 0, errExperimentalCLIInput
	}
	var height uint64
	var hash, provenance chain.Hash
	if decodeExperimentalCLIObject(frontier, map[string]any{
		"height": &height, "hash": &hash, "provenance_sha256": &provenance,
	}) != nil || height != selected.Height || hash != selected.Hash || provenance != out.ProvenanceSHA256 ||
		captured.Stream != out.Stream || captured.Provenance != provenance || captured.Space != "effective-raw-ledger" ||
		captured.Records == 0 || captured.Records > 100000000 || captured.Records > out.Stream.Bytes/3 {
		return 0, errExperimentalCLIInput
	}
	var recounted snapshotInventorySelection
	var records, readBytes uint64
	var selectionMatched, eof bool
	if decodeExperimentalCLIObject(inventory, map[string]any{
		"format": &format, "status": &status, "selection": &recounted, "selection_matched": &selectionMatched,
		"end_of_stream_observed": &eof, "records": &records, "input_bytes": &readBytes,
		"families": new(json.RawMessage), "limits": new(json.RawMessage), "storage_suffix_bytes": new(json.RawMessage),
		"top_level_prefix_counts": new(json.RawMessage), "account_subprefix_counts": new(json.RawMessage),
		"distinct_typed_balance_addresses": new(json.RawMessage), "distinct_tokens_computed": new(json.RawMessage),
		"byte_accounting": new(json.RawMessage), "histogram_method": new(json.RawMessage),
		"quantile_method": new(json.RawMessage), "scope": new(json.RawMessage),
	}) != nil || format != "zenon-effective-ledger-inventory/v1" || status != "SELECTED_STREAM_INVENTORIED" ||
		!selectionMatched || !eof || records != captured.Records || readBytes != out.Stream.Bytes || recounted != captured {
		return 0, errExperimentalCLIInput
	}
	return records, nil
}

func checkSnapshotProjectionRoot(raw []byte, records uint64, selected *snapshotProjectionSelection) error {
	var expected, mapping chain.Hash
	var qualification string
	var matched, accepted, excluded bool
	var leaves, balances, storage, empty, limit, files uint64
	if decodeExperimentalCLIObject(raw, map[string]any{
		"profile": &selected.Comparison.Profile, "qualification": &qualification,
		"expected_root": &expected, "computed_root": &selected.Root, "mapping_sha256": &mapping,
		"leaves": &leaves, "balance_prefix_leaves": &balances, "contract_storage_leaves": &storage,
		"empty_folded_records": &empty, "max_leaves": &limit, "value_files_written": &files,
		"raw_frontier_metadata_matched": &matched, "accepted_header_binding": &accepted,
		"excluded_state_authenticated": &excluded,
	}) != nil || selected.Comparison.Profile != experimentalSnapshotProjectionProfile || qualification != "MATH_ONLY" ||
		expected != selected.Root || mapping.IsZero() || limit == 0 || limit > 100000 || leaves > limit ||
		balances > leaves || storage != leaves-balances || leaves >= records || empty >= records-leaves ||
		files != 0 || !matched || accepted || excluded {
		return errExperimentalCLIInput
	}
	return nil
}
