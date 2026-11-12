// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/0x3639/zenon-spv/internal/proof"
)

// ExperimentalBatchEntrySourceRule selects a bounded subset of the phase1
// source rules shared by the two supported experimental node revisions.
// It does not verify submission
// authorization, state transitions, execution, registration or finality.
const ExperimentalBatchEntrySourceRule = "zenon-phase1-batch-fields/v1"

var ErrExperimentalBatchEntrySourceRule = errors.New("BatchEntry differs from the selected source-field rule")

// Applied only after a canonical membership proof and bounded strict ABI decode.
// An empty rule preserves the version 1 profile's ABI-only interpretation.
func experimentalBatchEntrySourceRule(entry proof.CandidateBatchEntry, rule string) error {
	if rule == "" {
		return nil
	}
	if rule != ExperimentalBatchEntrySourceRule || len(entry.ProofData) != 0 ||
		!experimentalBatchPillarName(entry.ExecutorPillar) || !experimentalBatchAssetFlow(entry.AssetFlowSummary) {
		return ErrExperimentalBatchEntrySourceRule
	}
	return nil
}

// The source checkPillarName uses ^([a-zA-Z0-9]+[-._]?)*[a-zA-Z0-9]$
// and PillarNameLengthMax = 40. Work here is bounded by that byte ceiling.
func experimentalBatchPillarName(name string) bool {
	if len(name) == 0 || len(name) > 40 {
		return false
	}
	previousAlnum := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !alnum && (!previousAlnum || (c != '-' && c != '.' && c != '_')) {
			return false
		}
		previousAlnum = alnum
	}
	return previousAlnum
}

// Source decodeAssetFlowSummary: u32BE count <= 16, followed by exactly n
// 96-byte entries (asset ID, deposit u256BE, withdrawal u256BE). ZTSFromAssetId
// requires 22 zero prefix bytes; IDs are strictly increasing; amounts cannot
// both be zero. No current token registry or deposit/execution check is implied.
func experimentalBatchAssetFlow(raw []byte) bool {
	if len(raw) < 4 {
		return false
	}
	n := binary.BigEndian.Uint32(raw[:4])
	if n > 16 || len(raw) != 4+96*int(n) {
		return false
	}
	var zeroPrefix [22]byte
	var zeroAmounts [64]byte
	var previous []byte
	for i := 0; i < int(n); i++ {
		entry := raw[4+96*i : 4+96*(i+1)]
		id := entry[:32]
		if !bytes.Equal(id[:22], zeroPrefix[:]) || (i != 0 && bytes.Compare(previous, id) >= 0) ||
			bytes.Equal(entry[32:], zeroAmounts[:]) {
			return false
		}
		previous = id
	}
	return true
}
