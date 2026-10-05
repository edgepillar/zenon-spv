//go:build !darwin && !linux

package main

import "os"

// Common checks require regular files before and after opening. Native FIFO
// replacement and final-component no-follow controls only run on Linux/macOS.
func openReadOnlyInput(path string) (*os.File, error) { return os.Open(path) }
