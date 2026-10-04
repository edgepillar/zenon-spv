//go:build darwin || linux

package conformance_test

import (
	"syscall"
	"testing"
)

func makeStateInputFIFO(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal("cannot create compiled state-input FIFO control")
	}
}
