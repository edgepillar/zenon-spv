// SPDX-License-Identifier: MIT

package verify

import (
	"encoding/json"
	"io"

	"github.com/0x3639/zenon-spv/internal/chain"
)

const experimentalV3ExportSource = "exported experimental checkpoint"

// WriteCheckpoint emits the existing bounded version-4 checkpoint schema to a
// caller-owned stream. It replaces the informational Source label with a fixed
// label so private provenance text is not exported. Source does not select
// verification behavior or context identity. Save retains its original label.
//
// The caller must retain a successful exit and complete output before using the
// bytes. A failed write may leave partial output. A digest identifies bytes, not
// their provenance or evicted ancestry. Later import still requires independently
// selected settings, context and digest plus trusted local provenance. Header
// verification is not repeated here and the immutable state is not modified.
func (s ExperimentalV3State) WriteCheckpoint(destination io.Writer) error {
	if s.data == nil {
		return ErrUninitializedState
	}
	profile := s.data.config.profile
	profile.Source = experimentalV3ExportSource
	return s.encodeExperimentalV3Checkpoint(destination, profile)
}

func (s ExperimentalV3State) encodeExperimentalV3Checkpoint(destination io.Writer, profile ExperimentalV3Profile) error {
	if s.data == nil {
		return ErrUninitializedState
	}
	if destination == nil {
		return io.ErrClosedPipe
	}
	headers := s.data.headers
	if headers == nil {
		headers = []chain.CandidateV3Header{}
	}
	body := experimentalV3File{Format: experimentalV3StateFormat, Version: 4, Context: s.data.config.context.Fingerprint,
		Profile: profile, Policy: s.data.config.policy, Headers: headers}
	encoder := json.NewEncoder(&limitedStateWriter{
		destination: experimentalV3CompleteWriter{destination}, remaining: MaxExperimentalV3StateBytes,
	})
	encoder.SetIndent("", "  ")
	return encoder.Encode(body)
}

// json.Encoder relies on its destination to report short writes as errors.
// A general caller-owned stream needs this check even when os.File did not.
type experimentalV3CompleteWriter struct{ destination io.Writer }

func (w experimentalV3CompleteWriter) Write(raw []byte) (int, error) {
	n, err := w.destination.Write(raw)
	if n < 0 || n > len(raw) {
		return 0, io.ErrShortWrite
	}
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	return n, err
}
