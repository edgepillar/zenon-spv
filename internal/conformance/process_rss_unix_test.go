//go:build linux || darwin

package conformance_test

import (
	"os"
	"runtime"
	"syscall"
)

// Use this exited child's accounting, not aggregate RUSAGE_CHILDREN or a
// sampler that can miss a short-lived maximum. Linux reports KiB; Darwin
// reports bytes. This does not include the test parent's fixture allocations.
func processPeakRSS(state *os.ProcessState) *uint64 {
	if state == nil {
		return nil
	}
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || usage.Maxrss <= 0 {
		return nil
	}
	peak := uint64(usage.Maxrss)
	if runtime.GOOS == "linux" {
		peak *= 1024
	}
	return &peak
}
