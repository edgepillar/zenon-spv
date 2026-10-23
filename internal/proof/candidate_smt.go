// SPDX-License-Identifier: MIT

package proof

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/bits"

	"github.com/0x3639/zenon-spv/internal/chain"
	"golang.org/x/crypto/sha3"
)

const (
	// CandidateSMTMaxValueBytes is a local research-work ceiling, not a
	// protocol balance range. The recorded node also represents 33-byte values.
	CandidateSMTMaxValueBytes = 4096
	CandidateSMTMaxProofBytes = 103 + 256*chain.HashSize + CandidateSMTMaxValueBytes
)

var (
	ErrCandidateSMTBounds   = errors.New("candidate SMT proof exceeds explicit research limits")
	ErrCandidateSMTEncoding = errors.New("malformed candidate SMT proof encoding")
	ErrCandidateSMTPath     = errors.New("candidate SMT proof path differs from selected path")
	ErrCandidateSMTMismatch = errors.New("candidate SMT proof differs from selected root or value")
)

// CandidateSMTLimits requires explicit positive byte caps. Zero never disables
// a cap. These limits select bounded local work; they do not register a network
// profile, choose a canonical-proof policy, or authorize a balance value width.
type CandidateSMTLimits struct {
	MaxProofBytes int
	MaxValueBytes int
}

// CandidateSMTMatch describes a mathematical match to caller-selected inputs.
// Value is detached from the proof and caller's claim. Present distinguishes a
// stored zero or present-empty core leaf from absence. Canonical is false when
// the bitmap stores an explicit zero sibling, an equivalent encoding accepted
// by the recorded node. It is a fact, not a network acceptance decision.
//
// This type is not a verify.Result, accepted header, or owned VerifiedState.
// A successful comparison does not authenticate the selected root or path.
type CandidateSMTMatch struct {
	Present      bool
	Value        []byte
	Canonical    bool
	SiblingCount uint16
}

// CheckCandidateSMTInclusion checks a bounded path-native inclusion proof.
// path is already the SHA3-256 application-key position; it is not rehashed.
// root and value must be selected by the caller, not learned from this proof.
// The caller must not mutate input slices concurrently with this call.
//
// This pure candidate primitive performs no header, signature, activation,
// domain or consensus check. It does not enable VerifyStateValue or v3.
func CheckCandidateSMTInclusion(root, path chain.Hash, value, raw []byte, limits CandidateSMTLimits) (CandidateSMTMatch, error) {
	return checkCandidateSMT(root, path, value, raw, true, limits)
}

// CheckCandidateSMTAbsence checks a bounded path-native absence proof. Absence
// under a partial tree does not establish coverage of an application key domain.
// In particular, excluded plasma/frontier/mailbox keys can match mathematically.
func CheckCandidateSMTAbsence(root, path chain.Hash, raw []byte, limits CandidateSMTLimits) (CandidateSMTMatch, error) {
	return checkCandidateSMT(root, path, nil, raw, false, limits)
}

// CandidateBalanceClaim binds a candidate byte comparison to a locally selected
// address/token pair and explicit presence/value bytes. Root is still an
// unauthenticated caller input. No amount codec or maximum is inferred here.
type CandidateBalanceClaim struct {
	Root    chain.Hash
	Address chain.Address
	Token   chain.TokenStandard
	Present bool
	Value   []byte
}

// CandidateBalanceKey derives the exact 32-byte partial-tree balance key. The
// fixed-width types require callers to validate/checksum any textual inputs at
// their text boundary. This function neither parses text nor accepts a raw key.
func CandidateBalanceKey(address chain.Address, token chain.TokenStandard) [32]byte {
	var key [32]byte
	key[0] = 0x03
	copy(key[1:21], address[:])
	key[21] = 0x03
	copy(key[22:], token[:])
	return key
}

// CheckCandidateBalanceProof derives the balance path locally before checking
// the raw proof. A provider cannot replace it with a plasma/storage/frontier key
// through this interface. A matching caller-selected Root is not an accepted
// header root: accepted-header/context integration remains a separate gate.
func CheckCandidateBalanceProof(claim CandidateBalanceClaim, raw []byte, limits CandidateSMTLimits) (CandidateSMTMatch, error) {
	key := CandidateBalanceKey(claim.Address, claim.Token)
	path := chain.Hash(sha3.Sum256(key[:]))
	if claim.Present {
		return CheckCandidateSMTInclusion(claim.Root, path, claim.Value, raw, limits)
	}
	if len(claim.Value) != 0 {
		return CandidateSMTMatch{}, ErrCandidateSMTEncoding
	}
	return CheckCandidateSMTAbsence(claim.Root, path, raw, limits)
}

func checkCandidateSMT(root, path chain.Hash, value, raw []byte, present bool, limits CandidateSMTLimits) (CandidateSMTMatch, error) {
	if limits.MaxProofBytes < 99 || limits.MaxProofBytes > CandidateSMTMaxProofBytes ||
		limits.MaxValueBytes <= 0 || limits.MaxValueBytes > CandidateSMTMaxValueBytes ||
		len(raw) > limits.MaxProofBytes || len(value) > limits.MaxValueBytes {
		return CandidateSMTMatch{}, ErrCandidateSMTBounds
	}
	if len(raw) < 99 || raw[0] > 1 {
		return CandidateSMTMatch{}, ErrCandidateSMTEncoding
	}
	var encodedPath, leaf chain.Hash
	copy(encodedPath[:], raw[1:33])
	copy(leaf[:], raw[33:65])
	bitmap := raw[65:97]
	count := int(binary.BigEndian.Uint16(raw[97:99]))
	popcount := 0
	for _, b := range bitmap {
		popcount += bits.OnesCount8(b)
	}
	if count > 256 || count != popcount {
		return CandidateSMTMatch{}, ErrCandidateSMTEncoding
	}
	// count is bounded before multiplication or slicing on every architecture.
	offset := 99 + count*chain.HashSize
	if len(raw) < offset {
		return CandidateSMTMatch{}, ErrCandidateSMTEncoding
	}
	inclusion := raw[0] == 1
	var stored []byte
	if inclusion {
		if len(raw)-offset < 4 {
			return CandidateSMTMatch{}, ErrCandidateSMTEncoding
		}
		length := binary.BigEndian.Uint32(raw[offset : offset+4])
		if uint64(length) != uint64(len(raw)-offset-4) {
			return CandidateSMTMatch{}, ErrCandidateSMTEncoding
		}
		if length > uint32(limits.MaxValueBytes) {
			return CandidateSMTMatch{}, ErrCandidateSMTBounds
		}
		stored = raw[offset+4:]
		// Fixed local storage avoids allocation from the untrusted length.
		var preimage [chain.HashSize + CandidateSMTMaxValueBytes]byte
		copy(preimage[:chain.HashSize], encodedPath[:])
		copy(preimage[chain.HashSize:], stored)
		if chain.Hash(sha3.Sum256(preimage[:chain.HashSize+len(stored)])) != leaf {
			return CandidateSMTMatch{}, ErrCandidateSMTEncoding
		}
	} else if len(raw) != offset || !leaf.IsZero() {
		return CandidateSMTMatch{}, ErrCandidateSMTEncoding
	}
	if inclusion != present {
		return CandidateSMTMatch{}, ErrCandidateSMTEncoding
	}
	if encodedPath != path {
		return CandidateSMTMatch{}, ErrCandidateSMTPath
	}
	if present && !bytes.Equal(stored, value) {
		return CandidateSMTMatch{}, ErrCandidateSMTMismatch
	}
	current, cursor, canonical := leaf, 99, true
	for index := 0; index < 256; index++ {
		var sibling chain.Hash
		if bitmap[index/8]&(1<<uint(7-index%8)) != 0 {
			copy(sibling[:], raw[cursor:cursor+chain.HashSize])
			cursor += chain.HashSize
			canonical = canonical && !sibling.IsZero()
		}
		if current.IsZero() && sibling.IsZero() {
			continue
		}
		var pair [2 * chain.HashSize]byte
		if path[chain.HashSize-1-index/8]&(1<<uint(index%8)) != 0 {
			copy(pair[:chain.HashSize], sibling[:])
			copy(pair[chain.HashSize:], current[:])
		} else {
			copy(pair[:chain.HashSize], current[:])
			copy(pair[chain.HashSize:], sibling[:])
		}
		current = chain.Hash(sha3.Sum256(pair[:]))
	}
	if current != root {
		return CandidateSMTMatch{}, ErrCandidateSMTMismatch
	}
	return CandidateSMTMatch{Present: present, Value: bytes.Clone(stored), Canonical: canonical, SiblingCount: uint16(count)}, nil
}
