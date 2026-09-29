package chain

import (
	"errors"
	"fmt"
)

const AccountBlockVersion1 uint64 = 1

var (
	ErrUnsupportedAccountBlockVersion = errors.New("unsupported account-block version")
	ErrUnsupportedAccountBlockType    = errors.New("unsupported account-block type")
	ErrInvalidAccountBlockEnvelope    = errors.New("invalid account-block envelope")
)

// ValidateAccountBlockVersion gates the only implemented account layout.
// Momentum version 2 does not imply account-block version 2 support.
func ValidateAccountBlockVersion(version uint64) error {
	if version != AccountBlockVersion1 {
		return fmt.Errorf("%w: got %d, supported 1", ErrUnsupportedAccountBlockVersion, version)
	}
	return nil
}

// ValidateAccountBlockEnvelope checks context-free fields of a post-genesis
// account block. It does not prove parent existence, acknowledgement validity,
// send/receive execution, token semantics, PoW, or network membership.
func ValidateAccountBlockEnvelope(b AccountBlock) error {
	if err := ValidateAccountBlockVersion(b.Version); err != nil {
		return err
	}
	switch b.BlockType {
	case BlockTypeUserSend, BlockTypeUserReceive, BlockTypeContractSend, BlockTypeContractReceive:
	default:
		// Genesis account blocks need a separate trust path, not this segment API.
		return fmt.Errorf("%w: got %d, supported post-genesis types 2 through 5", ErrUnsupportedAccountBlockType, b.BlockType)
	}
	if b.ChainIdentifier == 0 {
		return fmt.Errorf("%w: chain identifier must be positive", ErrInvalidAccountBlockEnvelope)
	}
	if b.Height == 0 {
		return fmt.Errorf("%w: height must be positive", ErrInvalidAccountBlockEnvelope)
	}
	if (b.Height == 1) != b.PreviousHash.IsZero() {
		return fmt.Errorf("%w: height 1 requires a zero previous hash; higher heights require a nonzero hash", ErrInvalidAccountBlockEnvelope)
	}
	contractType := b.BlockType == BlockTypeContractSend || b.BlockType == BlockTypeContractReceive
	if b.Address.IsEmbeddedAddress() != contractType {
		return fmt.Errorf("%w: block type does not match account address kind", ErrInvalidAccountBlockEnvelope)
	}
	return nil
}
