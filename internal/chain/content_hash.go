package chain

import (
	"bytes"
	"cmp"
	"slices"

	"golang.org/x/crypto/sha3"
)

// MomentumContentHash mirrors go-zenon's MomentumContent.Hash —
// reference/go-zenon/chain/nom/momentum_content.go:29-55.
//
// Each AccountHeader serializes as address(20B) || uint64BE(height)
// || hash(32B) via AccountHeader.Bytes; the slice is sorted
// lexicographically by that byte representation (matching
// AccountBlockHeaderComparer); the SHA3-256 of the byte
// concatenation is the commitment root r_C that
// Momentum.ContentHash binds.
//
// Branch 7 of the peer-review-plan consolidated this into a single
// implementation. The verify and fetch packages previously kept
// byte-equivalent copies (verify.flatContentHash,
// fetch.contentHashOfDecoded); both now call through to this
// function. The duplication-by-construction is gone — any future
// change to the canonical content hashing lives here, in the
// dependency-free chain package, and both call sites pick it up
// automatically.
//
// Empty input returns SHA3-256 of zero bytes. This is the bound
// MomentumContent.Hash value of a momentum with no account blocks;
// the verifier relies on it to bind a "no content" momentum
// alongside any other content-bearing momentum.
func MomentumContentHash(headers []AccountHeader) Hash {
	d := sha3.New256()
	if len(headers) == 0 {
		var out Hash
		copy(out[:], d.Sum(nil))
		return out
	}
	// Sort indices so the caller's headers stay immutable and no canonical
	// byte slice needs to be allocated for each member. Numeric uint64 order
	// matches lexicographic order of the big-endian height bytes.
	order := make([]int, len(headers))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(i, j int) int {
		a, b := &headers[i], &headers[j]
		if c := bytes.Compare(a.Address[:], b.Address[:]); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Height, b.Height); c != 0 {
			return c
		}
		return bytes.Compare(a.Hash[:], b.Hash[:])
	})
	var row [AccountHeaderRawLen]byte
	for _, i := range order {
		headers[i].putBytes(&row)
		d.Write(row[:])
	}
	var out Hash
	copy(out[:], d.Sum(nil))
	return out
}
