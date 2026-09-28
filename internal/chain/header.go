package chain

import (
	"encoding/binary"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/sha3"
)

// HashSize is the canonical Zenon hash byte length.
//
// Mirrors reference/go-zenon/common/types/hash.go:11 (HashSize = 32).
const HashSize = 32

// Hash is a 32-byte SHA3-256 digest. Equivalent to types.Hash in
// reference/go-zenon/common/types/hash.go:14.
type Hash [HashSize]byte

// IsZero reports whether the hash is the all-zero value.
func (h Hash) IsZero() bool {
	var zero Hash
	return h == zero
}

// Bytes returns a slice view of h. The returned slice aliases h.
func (h Hash) Bytes() []byte { return h[:] }

// Header is the verifier-required subset of a v1 or v2 nom.Momentum.
//
// Field order and semantics mirror reference/go-zenon/chain/nom/momentum.go:32-51.
// The shim isolates the verifier from go-zenon's struct shape so the
// znn-sdk-go vs. go-zenon-direct dependency choice is a single-file decision.
type Header struct {
	Version         uint64 `json:"version"`
	ChainIdentifier uint64 `json:"chainIdentifier"`

	HeaderHash   Hash   `json:"hash"` // claimed; verifier recomputes and compares
	PreviousHash Hash   `json:"previousHash"`
	Height       uint64 `json:"height"`

	TimestampUnix uint64 `json:"timestamp"`

	DataHash    Hash `json:"dataHash"`    // hash of opaque Data field
	ContentHash Hash `json:"contentHash"` // = MomentumContent.Hash()
	ChangesHash Hash `json:"changesHash"` // opaque to SPV (state-mutation patch hash)

	PublicKey []byte `json:"publicKey"` // 32B ed25519
	Signature []byte `json:"signature"` // 64B ed25519

	NextFusionPrice uint64 `json:"nextFusionPrice"`
	NextWorkPrice   uint64 `json:"nextWorkPrice"`
}

// ComputeHash uses the version-aware nom.Momentum serialization
// (reference/go-zenon/chain/nom/momentum.go:58-69). It is a low-level
// hashing primitive and does not validate Version. Verification and
// RPC entry points must call ValidateHeaderVersion before using it.
// Version 2 appends NextFusionPrice and NextWorkPrice as uint64BE values.
// Verification additionally requires an explicit activation profile for v2.
//
// The signed envelope is the byte concatenation of, in order:
//
//	Uint64ToBytes(Version)
//	Uint64ToBytes(ChainIdentifier)
//	PreviousHash.Bytes()
//	Uint64ToBytes(Height)
//	Uint64ToBytes(TimestampUnix)
//	DataHash.Bytes()        // already a hash; no rehash here
//	ContentHash.Bytes()     // already a hash; already MomentumContent.Hash()
//	ChangesHash.Bytes()
//
// hashed via SHA3-256 (reference/go-zenon/common/crypto/hash.go:9-15).
//
// NOTE: nom.Momentum stores raw Data bytes and computes types.NewHash(Data)
// inline within ComputeHash. We carry the pre-hashed DataHash on Header
// since SPV does not need raw Data and trusts the producer's signature
// to bind it. This makes the SPV hash calculation a function of the
// retained subset only, matching the spec's "verifier-required subset"
// intent (spec/spv-implementation-guide.md §3.1).
func (h *Header) ComputeHash() Hash {
	var buf []byte
	buf = appendUint64(buf, h.Version)
	buf = appendUint64(buf, h.ChainIdentifier)
	buf = append(buf, h.PreviousHash.Bytes()...)
	buf = appendUint64(buf, h.Height)
	buf = appendUint64(buf, h.TimestampUnix)
	buf = append(buf, h.DataHash.Bytes()...)
	buf = append(buf, h.ContentHash.Bytes()...)
	buf = append(buf, h.ChangesHash.Bytes()...)
	if h.Version == MomentumVersion2 {
		buf = appendUint64(buf, h.NextFusionPrice)
		buf = appendUint64(buf, h.NextWorkPrice)
	}

	d := sha3.New256()
	d.Write(buf)
	var out Hash
	copy(out[:], d.Sum(nil))
	return out
}

// UnmarshalJSON requires explicit prices for v2. Missing or null prices must
// not silently become zero through proof bundles or persisted state.
func (h *Header) UnmarshalJSON(raw []byte) error {
	type plain Header
	var wire struct {
		plain
		Fusion *uint64 `json:"nextFusionPrice"`
		Work   *uint64 `json:"nextWorkPrice"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	if wire.Version == MomentumVersion2 && (wire.Fusion == nil || wire.Work == nil) {
		return errors.New("version 2 header requires nextFusionPrice and nextWorkPrice")
	}
	if wire.Fusion != nil {
		wire.NextFusionPrice = *wire.Fusion
	}
	if wire.Work != nil {
		wire.NextWorkPrice = *wire.Work
	}
	*h = Header(wire.plain)
	return nil
}

// appendUint64 mirrors common.Uint64ToBytes (big-endian, 8 bytes).
// reference/go-zenon/common/bytes.go:24-28.
func appendUint64(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(dst, b[:]...)
}
