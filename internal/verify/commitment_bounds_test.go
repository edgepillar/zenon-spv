package verify

import (
	"math"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func FuzzPreflightCommitmentBounds(f *testing.F) {
	f.Add(uint8(2), uint8(2), uint8(4), []byte{2, 130})
	f.Add(uint8(2), uint8(2), uint8(3), []byte{2, 130})
	f.Add(uint8(0), uint8(0), uint8(0), []byte{0, 4, 31})
	f.Add(uint8(255), uint8(255), uint8(255), []byte{0, 31, 255})
	f.Fuzz(func(t *testing.T, countCap, flatCap, totalCap uint8, shape []byte) {
		shape = shape[:min(len(shape), 64)]
		capValue := func(n uint8) int {
			if n == 255 {
				return math.MaxInt
			}
			return int(n)
		}
		policy := Policy{MaxCommitments: capValue(countCap), MaxFlatEvidenceMembers: capValue(flatCap), MaxTotalFlatEvidenceMembers: capValue(totalCap)}
		batch := make([]proof.CommitmentEvidence, len(shape))
		lengths := make([]int, len(shape))
		for i, b := range shape {
			if b&128 != 0 && i > 0 {
				batch[i].Flat = batch[i-1].Flat
			} else if b != 0 {
				batch[i].Flat = &proof.FlatContentEvidence{SortedHeaders: make([]chain.AccountHeader, int(b&31))}
			}
			if batch[i].Flat != nil {
				lengths[i] = len(batch[i].Flat.SortedHeaders)
			}
		}
		// The oracle uses a bounded sum (at most 64*31), independently of
		// the production remaining-capacity arithmetic. Aliases count twice.
		total, largest := 0, 0
		for _, n := range lengths {
			total += n
			largest = max(largest, n)
		}
		fits := (countCap == 0 || len(batch) <= policy.MaxCommitments) &&
			(flatCap == 0 || largest <= policy.MaxFlatEvidenceMembers) &&
			(totalCap == 0 || total <= policy.MaxTotalFlatEvidenceMembers)
		for range 2 {
			r := PreflightCommitmentBounds(batch, policy)
			want, reason := OutcomeRefused, ReasonOversizedEvidence
			if fits {
				want, reason = OutcomeAccept, ReasonOK
			}
			if r.Outcome != want || r.Reason != reason || r.FailedAt != -1 || len(r.Proven) != 0 || len(r.TrustAssumptions) != 0 {
				t.Fatalf("resource preflight differs from count oracle or claims proof: %v", r)
			}
			slices.Reverse(batch) // The resource verdict must not depend on order.
		}
	})
}
