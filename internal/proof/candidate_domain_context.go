// SPDX-License-Identifier: MIT

package proof

import (
	"encoding/binary"

	"github.com/0x3639/zenon-spv/internal/chain"
	"golang.org/x/crypto/sha3"
)

// CandidateSettlementDomainRecordKey derives the selected node's full 27-byte
// ledger key from a locally selected Settlement address and domain. The caller
// selects and authenticates the address/profile separately. This helper does
// not select a network, authenticate a value or enable accepted state proofs.
func CandidateSettlementDomainRecordKey(settlement chain.Address, domainID uint32) [27]byte {
	return candidateSettlementDomainKey(settlement, domainID, 0x01)
}

// CandidateSettlementDomainConfigKey derives the domainConfig ledger key under
// the same explicit local inputs. Its storage prefix differs from domainRecord.
func CandidateSettlementDomainConfigKey(settlement chain.Address, domainID uint32) [27]byte {
	return candidateSettlementDomainKey(settlement, domainID, 0x15)
}

func candidateSettlementDomainKey(settlement chain.Address, domainID uint32, prefix byte) [27]byte {
	var key [27]byte
	key[0] = 0x03
	copy(key[1:21], settlement[:])
	key[21], key[22] = 0x04, prefix
	binary.BigEndian.PutUint32(key[23:], domainID)
	return key
}

// CandidateSettlementDomainRecordPath hashes the complete locally derived
// ledger key exactly once. The candidate SMT checker consumes this path without
// hashing it again; a mathematical match supplies no header/context authority.
func CandidateSettlementDomainRecordPath(settlement chain.Address, domainID uint32) chain.Hash {
	key := CandidateSettlementDomainRecordKey(settlement, domainID)
	return chain.Hash(sha3.Sum256(key[:]))
}

// CandidateSettlementDomainConfigPath provides the corresponding path for
// domainConfig. Neither path proves the configuration used by an older batch.
func CandidateSettlementDomainConfigPath(settlement chain.Address, domainID uint32) chain.Hash {
	key := CandidateSettlementDomainConfigKey(settlement, domainID)
	return chain.Hash(sha3.Sum256(key[:]))
}
