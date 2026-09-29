package verify

import (
	"fmt"

	"github.com/0x3639/zenon-spv/internal/proof"
)

// PreflightCommitmentBounds checks count, per-flat, and aggregate flat-member
// limits before a caller indexes or evaluates a batch. All entries count,
// including duplicates, unused targets, and repeated references to one Flat.
// ACCEPT only means the resource bounds hold; it proves no commitment.
func PreflightCommitmentBounds(batch []proof.CommitmentEvidence, policy Policy) Result {
	if policy.MaxCommitments > 0 && len(batch) > policy.MaxCommitments {
		return refuse(ReasonOversizedEvidence, fmt.Sprintf("commitments=%d > MaxCommitments=%d", len(batch), policy.MaxCommitments))
	}
	remaining := policy.MaxTotalFlatEvidenceMembers
	for i, evidence := range batch {
		if evidence.Flat == nil {
			continue
		}
		n := len(evidence.Flat.SortedHeaders)
		if policy.MaxFlatEvidenceMembers > 0 && n > policy.MaxFlatEvidenceMembers {
			return refuse(ReasonOversizedEvidence, fmt.Sprintf("commitment[%d] flat members=%d > MaxFlatEvidenceMembers=%d", i, n, policy.MaxFlatEvidenceMembers))
		}
		if policy.MaxTotalFlatEvidenceMembers > 0 {
			// Subtract only after checking capacity. No accumulated sum or
			// limit+1 sentinel can overflow, including when the cap is MaxInt.
			if n > remaining {
				return refuse(ReasonOversizedEvidence, fmt.Sprintf("aggregate flat evidence members > MaxTotalFlatEvidenceMembers=%d", policy.MaxTotalFlatEvidenceMembers))
			}
			remaining -= n
		}
	}
	return accept()
}
