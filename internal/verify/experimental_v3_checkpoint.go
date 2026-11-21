// SPDX-License-Identifier: MIT

package verify

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// ErrExperimentalV3CheckpointDigest rejects a missing or different independently
// selected SHA-256 identity. A matching digest does not authenticate provenance.
var ErrExperimentalV3CheckpointDigest = errors.New("experimental v3 checkpoint SHA-256 mismatch")

// ErrExperimentalV3CheckpointInput identifies a failed or oversized stream
// before any checkpoint can be accepted.
var ErrExperimentalV3CheckpointInput = errors.New("could not read experimental v3 checkpoint")

// DecodePinnedTrustedExperimentalV3State resumes trusted local persistence from
// bounded bytes with independently selected settings, context and SHA-256 pins.
// The digest covers exactly the same bytes that are decoded, avoiding a second
// path read. Retained header hashes, signatures, producer authorization and links
// are rechecked by the existing trusted-state decoder. Evicted ancestry and file
// authenticity still require trusted local provenance; provider data must not be
// promoted to that trust class by copying its digest. The caller must not mutate
// raw concurrently while it is read. No input bytes are retained.
func DecodePinnedTrustedExperimentalV3State(raw []byte, profile ExperimentalV3Profile, policy ExperimentalV3Policy, schedule *ProducerSchedule, expectedContext chain.Hash, expectedSHA256 [sha256.Size]byte) (ExperimentalV3State, error) {
	if err := checkExperimentalV3CheckpointBytes(raw, expectedSHA256); err != nil {
		return ExperimentalV3State{}, err
	}
	selected, err := NewExperimentalV3State(profile, policy, schedule, expectedContext)
	if err != nil {
		return ExperimentalV3State{}, err
	}
	return decodeTrustedExperimentalV3State(raw, selected)
}

// DecodePinnedTrustedCheckpoint returns a separate state using the receiver's
// selected context and frozen producer schedule. It rechecks the checkpoint
// digest and all retained headers. The caller must select trusted local bytes
// and avoid mutating them concurrently.
func (s ExperimentalV3State) DecodePinnedTrustedCheckpoint(raw []byte, expectedSHA256 [sha256.Size]byte) (ExperimentalV3State, error) {
	if err := checkExperimentalV3CheckpointBytes(raw, expectedSHA256); err != nil {
		return ExperimentalV3State{}, err
	}
	return decodeTrustedExperimentalV3State(raw, s)
}

// ReadPinnedTrustedCheckpoint reads one trusted local checkpoint stream to EOF
// within the state byte cap and returns its byte count on success. It decodes
// into temporary fields while computing SHA-256. The digest must match before
// the selected context or any retained signature can authorize those fields.
// As with the byte API, the caller must independently select trusted provenance.
func (s ExperimentalV3State) ReadPinnedTrustedCheckpoint(r io.Reader, expectedSHA256 [sha256.Size]byte) (ExperimentalV3State, int64, error) {
	digest := sha256.New()
	var file experimentalV3File
	var parseErr error
	size, err := readBoundedState(io.TeeReader(r, digest), MaxExperimentalV3StateBytes, func(input io.Reader) {
		parseErr = file.decodeJSON(json.NewDecoder(bufio.NewReader(input)))
	})
	if err != nil {
		return ExperimentalV3State{}, 0, fmt.Errorf("%w: %w", ErrExperimentalV3CheckpointInput, err)
	}
	if expectedSHA256 == ([sha256.Size]byte{}) || [sha256.Size]byte(digest.Sum(nil)) != expectedSHA256 {
		return ExperimentalV3State{}, 0, ErrExperimentalV3CheckpointDigest
	}
	if s.data == nil {
		return ExperimentalV3State{}, 0, ErrUninitializedState
	}
	if parseErr != nil {
		return ExperimentalV3State{}, 0, parseErr
	}
	state, err := s.resumeExperimentalV3File(file)
	if err != nil {
		return ExperimentalV3State{}, 0, err
	}
	return state, size, nil
}

func checkExperimentalV3CheckpointBytes(raw []byte, expectedSHA256 [sha256.Size]byte) error {
	if int64(len(raw)) > MaxExperimentalV3StateBytes {
		return ErrStateFileTooLarge
	}
	if expectedSHA256 == ([sha256.Size]byte{}) || sha256.Sum256(raw) != expectedSHA256 {
		return ErrExperimentalV3CheckpointDigest
	}
	return nil
}
