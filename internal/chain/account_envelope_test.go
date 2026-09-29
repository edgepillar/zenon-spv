package chain

import (
	"errors"
	"math"
	"testing"
)

func TestAccountEnvelopeShapes(t *testing.T) {
	for _, kind := range []uint64{BlockTypeUserSend, BlockTypeUserReceive, BlockTypeContractSend, BlockTypeContractReceive} {
		for _, height := range []uint64{1, 2, math.MaxUint64} {
			b := AccountBlock{Version: 1, ChainIdentifier: 99, BlockType: kind, Height: height}
			if kind == BlockTypeContractSend || kind == BlockTypeContractReceive {
				b.Address[0] = ContractAddrByte
			}
			if height > 1 {
				b.PreviousHash[0] = 1
			}
			if err := ValidateAccountBlockEnvelope(b); err != nil {
				t.Fatalf("supported shape failed: kind=%d height=%d err=%v", kind, height, err)
			}
			b.Address[0] ^= 1
			if !errors.Is(ValidateAccountBlockEnvelope(b), ErrInvalidAccountBlockEnvelope) {
				t.Fatal("opposite account kind was accepted")
			}
		}
	}
	for _, version := range []uint64{0, 2, math.MaxUint64} {
		if !errors.Is(ValidateAccountBlockVersion(version), ErrUnsupportedAccountBlockVersion) {
			t.Fatal("unsupported account layout was accepted")
		}
	}
}
