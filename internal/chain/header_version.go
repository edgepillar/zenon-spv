package chain

import (
	"errors"
	"fmt"
)

// SupportedMomentumVersion identifies the only signed momentum layout
// implemented by this verifier. It is not a network activation assertion.
const SupportedMomentumVersion uint64 = 1

// ErrUnsupportedHeaderVersion distinguishes an unsupported momentum
// layout from a hash or signature mismatch.
var ErrUnsupportedHeaderVersion = errors.New("unsupported momentum version")

// ValidateHeaderVersion refuses layouts that this verifier cannot reconstruct.
// Supporting a serialization does not establish its activation on a network.
func ValidateHeaderVersion(version uint64) error {
	if version != SupportedMomentumVersion {
		return fmt.Errorf("%w: got %d, supported %d", ErrUnsupportedHeaderVersion, version, SupportedMomentumVersion)
	}
	return nil
}
