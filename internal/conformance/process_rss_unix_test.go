//go:build linux || darwin

package conformance_test

import (
	"os"
	"runtime"
	"syscall"
)

type processMemoryObserver struct{}

func startProcessMemory(*os.Process) processMemoryObserver { return processMemoryObserver{} }
func (*processMemoryObserver) close()                      {}

// Use this exited child's accounting, not aggregate RUSAGE_CHILDREN or a
// sampler that can miss a short-lived maximum. Linux reports KiB; Darwin
// reports bytes. This does not include the test parent's fixture allocations.
func (*processMemoryObserver) finish(state *os.ProcessState) processMemorySample {
	if state == nil {
		return unavailableProcessMemory()
	}
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || usage.Maxrss <= 0 {
		return unavailableProcessMemory()
	}
	peak := uint64(usage.Maxrss)
	if runtime.GOOS == "linux" {
		peak *= 1024
	}
	return processMemorySample{bytes: &peak, source: "process_rusage"}
}
