//go:build darwin || linux

package main

import (
	"os"
	"syscall"
)

// A FIFO replacement must not wait for a writer before descriptor validation.
// O_NOFOLLOW also preserves final-component symlink refusal at this boundary.
// O_NONBLOCK does not change ordinary regular-file reads.
func openReadOnlyInput(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
