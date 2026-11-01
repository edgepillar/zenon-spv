// SPDX-License-Identifier: MIT

package proof

import (
	"encoding/binary"

	"github.com/0x3639/zenon-spv/internal/chain"
	"golang.org/x/crypto/sha3"
)

// CandidateSettlementBatchEntryKey derives the selected node's 35-byte L1
// ledger key from a locally selected Settlement address, domain and batch.
// The address must come from the caller's independently selected profile.
// Fixed-width inputs leave textual/checksum validation at the caller boundary.
//
// This source-mapping helper does not choose a network or profile, authenticate
// the address, decode BatchEntry values or enable accepted state proofs.
func CandidateSettlementBatchEntryKey(settlement chain.Address, domainID uint32, batchID uint64) [35]byte {
	var key [35]byte
	key[0] = 0x03
	copy(key[1:21], settlement[:])
	key[21], key[22] = 0x04, 0x02
	binary.BigEndian.PutUint32(key[23:27], domainID)
	binary.BigEndian.PutUint64(key[27:35], batchID)
	return key
}

// CandidateSettlementBatchEntryPath hashes the complete L1 ledger key exactly
// once with SHA3-256. Pass the resulting path directly to the candidate SMT
// checker; its path-native interface does not hash that path again.
//
// A mathematical match still requires a separately authenticated header root,
// local query/context identity and strict typed ABI acceptance before use.
func CandidateSettlementBatchEntryPath(settlement chain.Address, domainID uint32, batchID uint64) chain.Hash {
	key := CandidateSettlementBatchEntryKey(settlement, domainID, batchID)
	return chain.Hash(sha3.Sum256(key[:]))
}
