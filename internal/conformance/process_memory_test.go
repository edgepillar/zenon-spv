package conformance_test

import (
	"os/exec"
	"time"
)

type processMemorySample struct {
	bytes  *uint64
	source string
}

func unavailableProcessMemory() processMemorySample {
	return processMemorySample{source: "unavailable"}
}

// Only the resource workloads use this runner. Acquire any native observation
// handle between Start and Wait: os/exec still owns the original child handle
// then, even if a very short-lived child has already exited. No concurrent
// Wait/Release is permitted. Finish before releasing the observation handle.
func runProcessWithMemory(cmd *exec.Cmd) (processMemorySample, time.Duration, error) {
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return unavailableProcessMemory(), time.Since(start), err
	}
	observer := startProcessMemory(cmd.Process)
	defer observer.close()
	err := cmd.Wait()
	elapsed := time.Since(start)
	return observer.finish(cmd.ProcessState), elapsed, err
}
