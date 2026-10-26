//go:build candidate_core_init_failure

// SPDX-License-Identifier: GPL-3.0-only
package chain

import "errors"

// CandidateCoreInitFailureCloseLedger selects an actual stopped ledger manager;
// it does not replace an Init return value or start any worker.
func CandidateCoreInitFailureCloseLedger(value Chain) error {
	c, ok := value.(*chain)
	if !ok {
		return errors.New("selected concrete chain required")
	}
	return c.chainManager.Stop()
}

func CandidateCoreInitFailureHandles(value Chain) (ledgerOpen, cacheOpen bool, err error) {
	c, ok := value.(*chain)
	if !ok {
		return false, false, errors.New("selected concrete chain required")
	}
	return c.chainManager.Frontier() != nil, c.cacheManager.DB() != nil, nil
}
