// SPDX-License-Identifier: MIT

package verify

import (
	"crypto/sha256"
	"errors"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// ErrExperimentalV3CheckpointDigest rejects a missing or different independently
// selected SHA-256 identity. A matching digest does not authenticate provenance.
var ErrExperimentalV3CheckpointDigest = errors.New("experimental v3 checkpoint SHA-256 mismatch")

// DecodePinnedTrustedExperimentalV3State resumes trusted local persistence from
// bounded bytes with independently selected settings, context and SHA-256 pins.
// The digest covers exactly the same bytes that are decoded, avoiding a second
// path read. Retained header hashes, signatures, producer authorization and links
// are rechecked by the existing trusted-state decoder. Evicted ancestry and file
// authenticity still require trusted local provenance; provider data must not be
// promoted to that trust class by copying its digest. The caller must not mutate
// raw concurrently while it is read. No input bytes are retained.
func DecodePinnedTrustedExperimentalV3State(raw []byte, profile ExperimentalV3Profile, policy ExperimentalV3Policy, schedule *ProducerSchedule, expectedContext chain.Hash, expectedSHA256 [sha256.Size]byte) (ExperimentalV3State, error) {
	if int64(len(raw)) > MaxExperimentalV3StateBytes {
		return ExperimentalV3State{}, ErrStateFileTooLarge
	}
	if expectedSHA256 == ([sha256.Size]byte{}) || sha256.Sum256(raw) != expectedSHA256 {
		return ExperimentalV3State{}, ErrExperimentalV3CheckpointDigest
	}
	selected, err := NewExperimentalV3State(profile, policy, schedule, expectedContext)
	if err != nil {
		return ExperimentalV3State{}, err
	}
	return decodeTrustedExperimentalV3State(raw, selected)
}
