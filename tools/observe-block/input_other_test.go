//go:build !darwin && !linux

package main

import "testing"

func TestObserverPreflightReplacements(t *testing.T) {
	for _, role := range preflightRoles {
		for _, mode := range []string{"selected-fifo", "replacement-fifo", "replacement-symlink"} {
			t.Run(role+"/"+mode, func(t *testing.T) {
				t.Skip("native FIFO and final-component no-follow controls run only on Linux/macOS; common descriptor controls still run")
			})
		}
	}
}
