// SPDX-License-Identifier: MIT

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

const experimentalContextExportCommand = "export-experimental-batch-context-state"
const experimentalContextExportUsage = "Usage: zenon-spv export-experimental-batch-context-state --config <path> --request <path> --expect-header-context <64-hex> --expect-query-context <64-hex> [--trusted-state <path> --expect-state-sha256 <64-hex>] [--compare-gateway] <bundle.json>\n"

type experimentalCLIStateInputReport struct {
	SHA256          string `json:"sha256"`
	Bytes           uint64 `json:"bytes"`
	ProviderHeaders uint32 `json:"provider_headers"`
	Trust           string `json:"trust"`
}

func readExperimentalCLIState(state verify.ExperimentalV3State, path string, sha chain.Hash) (verify.ExperimentalV3State, *experimentalCLIStateInputReport, int, string) {
	checkpoint, _, err := openExperimentalCLIInput(path, verify.MaxExperimentalV3StateBytes, openExperimentalCLIFile)
	if err != nil {
		return state, nil, 70, "invalid_input"
	}
	resumed, size, err := state.ReadPinnedTrustedCheckpoint(checkpoint, [sha256.Size]byte(sha))
	if closeErr := checkpoint.Close(); closeErr != nil || errors.Is(err, verify.ErrExperimentalV3CheckpointInput) {
		return state, nil, 70, "invalid_input"
	}
	if errors.Is(err, verify.ErrExperimentalV3CheckpointDigest) {
		return state, nil, 1, "digest_mismatch"
	}
	if err != nil || resumed.Empty() {
		return state, nil, 70, "invalid_checkpoint"
	}
	input := &experimentalCLIStateInputReport{SHA256: hex.EncodeToString(sha[:]), Bytes: uint64(size), Trust: "trusted_local_provenance_required"}
	return resumed, input, 0, ""
}

type experimentalCLIStateOutput struct {
	SHA256                 string `json:"sha256"`
	Bytes                  uint64 `json:"bytes"`
	Complete               bool   `json:"complete"`
	Trust                  string `json:"trust"`
	ProvenanceLabelRemoved bool   `json:"provenance_label_removed"`
}

func exportExperimentalCLIState(state verify.ExperimentalV3State, destination io.Writer) (*experimentalCLIStateOutput, error) {
	if destination == nil {
		return nil, io.ErrClosedPipe
	}
	digest := sha256.New()
	stream := &experimentalContextCheckpointCounter{destination: io.MultiWriter(destination, digest)}
	if err := state.WriteCheckpoint(stream); err != nil {
		return nil, err
	}
	return &experimentalCLIStateOutput{SHA256: hex.EncodeToString(digest.Sum(nil)), Bytes: stream.bytes,
		Complete: true, Trust: "trusted_local_provenance_required", ProvenanceLabelRemoved: true}, nil
}

type experimentalContextCheckpointCounter struct {
	destination io.Writer
	bytes       uint64
}

func (w *experimentalContextCheckpointCounter) Write(raw []byte) (int, error) {
	n, err := w.destination.Write(raw)
	if n < 0 || n > len(raw) {
		return 0, io.ErrShortWrite
	}
	w.bytes += uint64(n)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	return n, err
}
