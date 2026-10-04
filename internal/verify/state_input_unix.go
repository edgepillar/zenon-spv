//go:build darwin || linux

package verify

import (
	"os"
	"syscall"
)

// A FIFO replacement must not wait for a writer before the descriptor check.
// O_NONBLOCK does not change ordinary regular-file reads.
func openReadOnlyStateFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
