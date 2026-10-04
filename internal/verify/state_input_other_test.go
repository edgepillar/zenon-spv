//go:build !darwin && !linux

package verify

import "testing"

func TestStateInputFIFOOpenIsBounded(t *testing.T) {
	t.Skip("native FIFO subprocess controls only run on Linux/macOS; common descriptor controls still run")
}
