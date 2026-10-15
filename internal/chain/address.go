package chain

import (
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/sha3"
)

// AddressSize is the canonical Zenon address byte length, matching
// types.AddressSize in reference/go-zenon/common/types/address.go.
const AddressSize = 20

// AddressCoreSize is the post-prefix byte count: addr[1:20] holds the
// truncated SHA3-256 of the public key. Mirrors types.AddressCoreSize
// at reference/go-zenon/common/types/address.go:14.
const AddressCoreSize = 19

// Address-prefix bytes (addr[0]) per
// reference/go-zenon/common/types/address.go:18-20.
const (
	UserAddrByte     byte = 0
	ContractAddrByte byte = 1
)

// Address is the raw 20-byte form of a Zenon account address.
//
// On the wire (in HeaderBundle JSON), Address is represented as
// hex; bech32 ("z1...") is the canonical user-facing form but lives
// at the fetch layer (internal/fetch.DecodeZenonAddress) — keeping
// the verifier package free of bech32 keeps the trust boundary tight.
type Address [AddressSize]byte

// Bytes returns a slice view of a. The returned slice aliases a.
func (a Address) Bytes() []byte { return a[:] }

// IsZero reports whether the address is the all-zero value.
func (a Address) IsZero() bool {
	var zero Address
	return a == zero
}

// MarshalText emits Address as a lowercase hex string.
func (a Address) MarshalText() ([]byte, error) {
	text := make([]byte, 2*AddressSize)
	hex.Encode(text, a[:])
	return text, nil
}

// UnmarshalText accepts a hex string with optional 0x prefix.
func (a *Address) UnmarshalText(text []byte) error {
	if len(text) >= 2 && text[0] == '0' && text[1] == 'x' {
		text = text[2:]
	}
	if len(text) != 2*AddressSize {
		return errors.New("chain.Address: invalid hex length")
	}
	// Decode privately: hex.Decode may write a prefix before reporting an
	// invalid digit. A failed conversion must leave the receiver unchanged.
	var decoded Address
	if _, err := hex.Decode(decoded[:], text); err != nil {
		return err
	}
	*a = decoded
	return nil
}

// IsEmbeddedAddress reports whether a is an embedded-contract address
// (its first byte is ContractAddrByte). Mirrors types.IsEmbeddedAddress
// at reference/go-zenon/common/types/address.go:46-48. Embedded-contract
// blocks must carry empty PublicKey/Signature per go-zenon's
// verifier/account_block.go:401-409 — the consensus layer signs them
// implicitly via the producer momentum.
func (a Address) IsEmbeddedAddress() bool {
	return a[0] == ContractAddrByte
}

// PubKeyToAddress derives a user-account address from an Ed25519
// public key. Mirrors types.PubKeyToAddress at
// reference/go-zenon/common/types/address.go:110-118 byte-for-byte:
//
//	addr[0] = UserAddrByte (0x00)
//	addr[1:20] = sha3.Sum256(pubKey)[0:19]
//
// Used by VerifySegment to bind block.PublicKey to block.Address —
// the missing check that go-zenon's verifier enforces with
// ErrABPublicKeyWrongAddress (verifier/account_block.go:445-447).
func PubKeyToAddress(pubKey []byte) Address {
	hash := sha3.Sum256(pubKey)
	var a Address
	a[0] = UserAddrByte
	copy(a[1:], hash[:AddressCoreSize])
	return a
}
