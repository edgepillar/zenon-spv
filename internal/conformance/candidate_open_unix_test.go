//go:build darwin || linux

package conformance_test

import (
	"os"
	"syscall"
)

// Do not wait for a substituted FIFO writer or follow a final symlink.
func openCandidateBinaryInput(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
