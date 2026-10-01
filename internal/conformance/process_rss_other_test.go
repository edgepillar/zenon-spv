//go:build !linux && !darwin

package conformance_test

import "os"

// Windows still executes every workflow. Its Go ProcessState.SysUsage does
// not expose peak resident memory; unavailable must not become a zero sample.
func processPeakRSS(*os.ProcessState) *uint64 { return nil }
