package chain

import (
	"errors"
	"fmt"
)

// These constants identify implemented layouts, not network activation.
const (
	MomentumVersion1 uint64 = 1
	MomentumVersion2 uint64 = 2
)

// ErrUnsupportedHeaderVersion distinguishes an unsupported momentum
// layout from a hash or signature mismatch.
var ErrUnsupportedHeaderVersion = errors.New("unsupported momentum version")

// ValidateHeaderVersion refuses layouts that this verifier cannot reconstruct.
// Supporting a serialization does not establish its activation on a network.
func ValidateHeaderVersion(version uint64) error {
	if version != MomentumVersion1 && version != MomentumVersion2 {
		return fmt.Errorf("%w: got %d, supported 1 and 2", ErrUnsupportedHeaderVersion, version)
	}
	return nil
}
