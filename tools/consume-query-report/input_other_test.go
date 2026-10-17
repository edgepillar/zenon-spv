//go:build !darwin && !linux

package main

import "testing"

func TestConsumerInputFIFOOpenIsBounded(t *testing.T) {
	for _, control := range []struct{ name, id string }{
		{"selected", "consumer_fifo_selected"},
		{"replacement", "consumer_fifo_replacement"},
		{"symlink replacement", "consumer_fifo_symlink_replacement"},
	} {
		t.Run(control.name, func(t *testing.T) {
			t.Log("offline-pilot-skip v1 control=" + control.id + " reason=native_fifo_nofollow_unavailable")
			t.Skip("native FIFO and final-component no-follow subprocess controls run only on Linux/macOS; common descriptor controls still run")
		})
	}
}
