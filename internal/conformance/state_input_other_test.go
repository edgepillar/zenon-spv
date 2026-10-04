//go:build !darwin && !linux

package conformance_test

import "testing"

func makeStateInputFIFO(t *testing.T, _ string) {
	t.Helper()
	t.Skip("native FIFO state-input controls only run on Linux/macOS; directory controls still run")
}
