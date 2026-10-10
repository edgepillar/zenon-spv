//go:build darwin || linux

package main

import (
	"os"
	"syscall"
)

// A replacement FIFO must reach descriptor validation without waiting for a
// writer. Refuse a final-component symlink at open, even if it appeared after
// Lstat. These flags do not impose an I/O deadline on ordinary-file reads.
func openPreflightInput(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
