//go:build !linux && !darwin && !windows

package conformance_test

import "os"

type processMemoryObserver struct{}

func startProcessMemory(*os.Process) processMemoryObserver { return processMemoryObserver{} }
func (*processMemoryObserver) close()                      {}

// Unsupported platforms must not turn unavailable accounting into zero.
func (*processMemoryObserver) finish(*os.ProcessState) processMemorySample {
	return unavailableProcessMemory()
}
