package main

import "strconv"

type advanceConfiguration struct {
	enabled                 bool
	safetyMargin, batchSize string
}

// State advancement is opt-in and limited to the already explicit RPC mode.
// No watch policy, endpoint, trust input, or retry is inferred from a report.
func validAdvanceSelection(c configuration, seen map[string]bool, retention int) bool {
	selected := seen["advance-state-once"] || seen["watch-safety-margin"] || seen["watch-batch-size"]
	if !selected {
		return !c.advance.enabled
	}
	if !c.advance.enabled || !seen["advance-state-once"] || !seen["watch-safety-margin"] || !seen["watch-batch-size"] || c.collection.binary == "" {
		return false
	}
	margin, err := strconv.ParseUint(c.advance.safetyMargin, 10, 64)
	if err != nil || strconv.FormatUint(margin, 10) != c.advance.safetyMargin {
		return false
	}
	batch, err := strconv.ParseUint(c.advance.batchSize, 10, 64)
	return err == nil && strconv.FormatUint(batch, 10) == c.advance.batchSize && batch > 0 && batch <= uint64(retention)
}

func advanceArguments(c configuration) []string {
	return []string{"watch", "--json", "--once", "--rpc", c.collection.rpc, "--quorum", "1",
		"--genesis-config", c.anchor, "--protocol-profile", c.profile, "--schedule", c.schedule,
		"--state", c.state, "--expect-context", c.pin, "--window", c.window, "--retain-headers", c.retention,
		"--safety-margin", c.advance.safetyMargin, "--batch-size", c.advance.batchSize}
}
