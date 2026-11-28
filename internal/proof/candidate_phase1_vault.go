// SPDX-License-Identifier: MIT

package proof

import (
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// CandidatePhase1VaultInterfaceSHA256 identifies the pinned example vault
// interface. Its storage layout applies to a caller-selected deployment.
const CandidatePhase1VaultInterfaceSHA256 = "26f4d8c1b1d1cbf9dcf2ed4d99fcbc4b8e81af5bfb476c756bfd99b759fefba9"

type CandidatePhase1VaultSelection struct {
	ContractID    chain.Hash
	Account       chain.Address
	TokenStandard chain.TokenStandard
}

func ParseCandidatePhase1VaultSelection(contract, account, token string) (CandidatePhase1VaultSelection, error) {
	var selection CandidatePhase1VaultSelection
	if !decodeVaultSelectionHex(selection.ContractID[:], contract) || selection.ContractID.IsZero() ||
		!decodeVaultSelectionHex(selection.Account[:], account) || !decodeVaultSelectionHex(selection.TokenStandard[:], token) {
		return CandidatePhase1VaultSelection{}, errors.New("invalid Phase 1 vault selection")
	}
	return selection, nil
}

func decodeVaultSelectionHex(dst []byte, text string) bool {
	if len(text) != 2*len(dst) || strings.ContainsAny(text, "ABCDEF") {
		return false
	}
	_, err := hex.Decode(dst, []byte(text))
	return err == nil
}

// LocalKey derives the pinned vault's balances key. The account is mapped to
// the L1 caller hash and the token is left-padded to the 32-byte asset ID.
func (s CandidatePhase1VaultSelection) LocalKey() [32]byte {
	const prefix = "L1_CALLER:"
	var caller [len(prefix) + chain.AddressSize]byte
	copy(caller[:], prefix)
	copy(caller[len(prefix):], s.Account[:])
	account := sha3.Sum256(caller[:])

	var key [1 + 2*chain.HashSize]byte
	key[0] = 1 // balances namespace
	copy(key[1:], account[:])
	copy(key[len(key)-chain.TokenStandardSize:], s.TokenStandard[:])
	return sha3.Sum256(key[:])
}

// CandidatePhase1StoragePath hashes the contract ID and the caller-selected
// local WASM key. A derived path grants no root or deployment authority.
func CandidatePhase1StoragePath(contractID chain.Hash, localKey []byte) chain.Hash {
	h := sha3.New256()
	_, _ = h.Write(contractID[:])
	_, _ = h.Write(localKey)
	return chain.Hash(h.Sum(nil))
}
