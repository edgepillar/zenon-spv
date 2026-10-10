//go:build darwin || linux

package main

import (
	"os"
	"syscall"
)

// A replacement FIFO cannot wait for a writer before descriptor validation.
// Refuse a final-component symlink at open; ordinary-file I/O has no deadline.
func openSourceInput(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
