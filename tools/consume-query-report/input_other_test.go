//go:build !darwin && !linux

package main

import "testing"

func TestConsumerInputFIFOOpenIsBounded(t *testing.T) {
	for _, mode := range []string{"selected", "replacement", "symlink replacement"} {
		t.Run(mode, func(t *testing.T) {
			t.Skip("native FIFO and final-component no-follow subprocess controls run only on Linux/macOS; common descriptor controls still run")
		})
	}
}
