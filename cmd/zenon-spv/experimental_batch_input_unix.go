//go:build darwin || linux

// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"syscall"
)

// A replaced FIFO cannot wait for a writer before the descriptor check.
func openExperimentalCLIFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
