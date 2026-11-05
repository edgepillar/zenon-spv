// SPDX-License-Identifier: MIT

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/0x3639/zenon-spv/internal/verify"
)

const experimentalContextExportCommand = "export-experimental-batch-context-state"
const experimentalContextExportUsage = "Usage: zenon-spv export-experimental-batch-context-state --config <path> --request <path> --expect-header-context <64-hex> --expect-query-context <64-hex> [--trusted-state <path> --expect-state-sha256 <64-hex>] [--compare-gateway] <bundle.json>\n"

type experimentalContextStateOutput struct {
	SHA256                 string `json:"sha256"`
	Bytes                  uint64 `json:"bytes"`
	Complete               bool   `json:"complete"`
	Trust                  string `json:"trust"`
	ProvenanceLabelRemoved bool   `json:"provenance_label_removed"`
}

func exportExperimentalContextState(state verify.ExperimentalV3State, destination io.Writer) (*experimentalContextStateOutput, error) {
	if destination == nil {
		return nil, io.ErrClosedPipe
	}
	digest := sha256.New()
	stream := &experimentalContextCheckpointCounter{destination: io.MultiWriter(destination, digest)}
	if err := state.WriteCheckpoint(stream); err != nil {
		return nil, err
	}
	return &experimentalContextStateOutput{SHA256: hex.EncodeToString(digest.Sum(nil)), Bytes: stream.bytes,
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
