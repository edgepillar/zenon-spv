package chain

import (
	"encoding/binary"
)

// AccountHeaderRawLen is the byte length of an AccountHeader's
// canonical encoding (mirrors types.AccountBlockHeaderRawLen at
// reference/go-zenon/chain/nom/momentum_content.go:10).
const AccountHeaderRawLen = AddressSize + HashSize + 8

// AccountHeader is the (address, height, hash) triple committed in a
// Momentum's Content slice — the unit of commitment-membership proofs.
//
// Mirrors types.AccountHeader at
// reference/go-zenon/common/types/account_header.go:9-12.
type AccountHeader struct {
	Address Address `json:"address"`
	Height  uint64  `json:"height"`
	Hash    Hash    `json:"hash"`
}

// Bytes returns the canonical 60-byte encoding used in
// MomentumContent.Hash. Mirrors types.AccountHeader.Bytes at
// reference/go-zenon/common/types/account_header.go:41-46:
//
//	address (20B) || uint64BE(height) (8B) || hash (32B)
func (a AccountHeader) Bytes() []byte {
	var out [AccountHeaderRawLen]byte
	a.putBytes(&out)
	return out[:]
}

// putBytes fills the entire canonical row without allocating a member buffer.
// Both Bytes and the content hasher use the same encoding.
func (a AccountHeader) putBytes(out *[AccountHeaderRawLen]byte) {
	copy(out[:AddressSize], a.Address[:])
	binary.BigEndian.PutUint64(out[AddressSize:AddressSize+8], a.Height)
	copy(out[AddressSize+8:], a.Hash[:])
}

// Equal reports whether a and b are byte-identical.
func (a AccountHeader) Equal(b AccountHeader) bool {
	return a.Address == b.Address && a.Height == b.Height && a.Hash == b.Hash
}
