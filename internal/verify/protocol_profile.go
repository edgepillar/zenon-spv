package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// ProtocolProfile is an operator-attested activation policy bound to an exact
// anchor and a finite coverage range. V2FromHeight is the FIRST v2 momentum
// height, not a spork enforcement height. Zero explicitly selects v1 throughout
// the covered range. This configuration is never inferred from peer data.
type ProtocolProfile struct {
	Version      uint32           `json:"version"`
	Anchor       GenesisTrustRoot `json:"anchor"`
	ValidThrough uint64           `json:"valid_through"`
	V2FromHeight uint64           `json:"v2_from_height"`
	Source       string           `json:"source"`
}

// MaxProtocolProfileBytes bounds a profile file and an embedded profile object.
const MaxProtocolProfileBytes = 16 * 1024

// UnmarshalJSON requires every field, including an explicit zero for a v1-only
// profile or a custom chain ID zero. It rejects ambiguous fields and applies
// the same byte limit to profiles embedded in retained state. Validation of
// the resulting policy remains separate; decoding alone grants no authority.
func (p *ProtocolProfile) UnmarshalJSON(raw []byte) error {
	if len(raw) > MaxProtocolProfileBytes {
		return fmt.Errorf("%w: profile exceeds 16 KiB", ErrInvalidProtocolProfile)
	}
	var next ProtocolProfile
	var anchor json.RawMessage
	if err := decodeRequiredObject(raw, map[string]any{
		"version": &next.Version, "anchor": &anchor, "valid_through": &next.ValidThrough,
		"v2_from_height": &next.V2FromHeight, "source": &next.Source,
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProtocolProfile, err)
	}
	var err error
	next.Anchor, err = decodeGenesisConfig(anchor)
	if err != nil {
		return fmt.Errorf("%w: anchor: %v", ErrInvalidProtocolProfile, err)
	}
	*p = next
	return nil
}

var (
	ErrProtocolProfileRequired = errors.New("version 2 requires an explicit protocol profile")
	ErrInvalidProtocolProfile  = errors.New("invalid protocol profile")
	ErrProtocolProfileMismatch = errors.New("protocol profile mismatch")
	ErrProtocolProfileCoverage = errors.New("header outside protocol profile coverage")
	ErrHeaderVersionInactive   = errors.New("momentum version does not match activation profile")
	ErrInvalidResourcePrice    = errors.New("invalid momentum resource price")
)

func (p ProtocolProfile) Validate() error {
	if p.Version != 1 || p.Anchor.HeaderHash.IsZero() || p.Anchor.Height == 0 ||
		p.ValidThrough <= p.Anchor.Height || p.V2FromHeight == 1 ||
		strings.TrimSpace(p.Source) == "" || len(p.Source) > 1024 {
		return ErrInvalidProtocolProfile
	}
	return nil
}

// LoadProtocolProfile accepts one bounded JSON object with known fields only.
// Source records provenance; its contents do not authenticate the policy.
func LoadProtocolProfile(path string) (*ProtocolProfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, MaxProtocolProfileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxProtocolProfileBytes {
		return nil, fmt.Errorf("%w: file exceeds 16 KiB", ErrInvalidProtocolProfile)
	}
	var p ProtocolProfile
	if err := json.Unmarshal(raw, &p); err != nil {
		if errors.Is(err, ErrInvalidProtocolProfile) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: malformed profile JSON", ErrInvalidProtocolProfile)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func cloneProtocolProfile(p *ProtocolProfile) *ProtocolProfile {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}

func sameProtocolProfile(a, b *ProtocolProfile) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func validateProfileAnchor(p *ProtocolProfile, anchor GenesisTrustRoot) error {
	if p == nil {
		return nil
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Anchor != anchor {
		return fmt.Errorf("%w: configured anchor differs", ErrProtocolProfileMismatch)
	}
	return nil
}

func validateProtocolHeader(h chain.Header, p *ProtocolProfile) error {
	if err := chain.ValidateHeaderVersion(h.Version); err != nil {
		return err
	}
	if p == nil {
		if h.Version == chain.MomentumVersion2 {
			return ErrProtocolProfileRequired
		}
	} else {
		if h.ChainIdentifier != p.Anchor.ChainID {
			return fmt.Errorf("%w: header chain ID differs", ErrProtocolProfileMismatch)
		}
		if h.Height <= p.Anchor.Height || h.Height > p.ValidThrough {
			return fmt.Errorf("%w: height=%d", ErrProtocolProfileCoverage, h.Height)
		}
		want := chain.MomentumVersion1
		if p.V2FromHeight != 0 && h.Height >= p.V2FromHeight {
			want = chain.MomentumVersion2
		}
		if h.Version != want {
			return fmt.Errorf("%w: height=%d got=%d want=%d", ErrHeaderVersionInactive, h.Height, h.Version, want)
		}
	}
	// The pinned node requires zero prices in v1 and MinResourcePrice=1000 in v2.
	// This does not re-execute the dynamic pricing state transition.
	if (h.Version == 1 && (h.NextFusionPrice != 0 || h.NextWorkPrice != 0)) ||
		(h.Version == 2 && (h.NextFusionPrice < 1000 || h.NextWorkPrice < 1000)) {
		return ErrInvalidResourcePrice
	}
	return nil
}

func (s HeaderState) validateProtocolPolicy(policy Policy) error {
	if !sameProtocolProfile(s.ProtocolProfile, policy.ProtocolProfile) {
		return ErrProtocolProfileMismatch
	}
	return s.ValidateHeaderVersions()
}

func protocolFailure(err error) Result {
	reason := ReasonInvalidProtocolProfile
	switch {
	case errors.Is(err, chain.ErrUnsupportedHeaderVersion):
		reason = ReasonUnsupportedHeaderVersion
	case errors.Is(err, ErrProtocolProfileRequired):
		reason = ReasonProtocolProfileRequired
	case errors.Is(err, ErrProtocolProfileMismatch):
		reason = ReasonProtocolProfileMismatch
	case errors.Is(err, ErrProtocolProfileCoverage):
		reason = ReasonProtocolProfileCoverage
	case errors.Is(err, ErrHeaderVersionInactive):
		return reject(ReasonHeaderVersionInactive, -1, err.Error())
	case errors.Is(err, ErrInvalidResourcePrice):
		return reject(ReasonInvalidResourcePrice, -1, err.Error())
	}
	return refuse(reason, err.Error())
}

func withProtocolTrust(r Result, p *ProtocolProfile) Result {
	if p != nil && r.Outcome == OutcomeAccept {
		return r.WithTrust(TrustExternalProtocolProfile)
	}
	return r
}
