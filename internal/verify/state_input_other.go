//go:build !darwin && !linux

package verify

import "os"

// The shared checks still require regular files before and after opening.
// Native FIFO replacement behavior is only exercised on Linux/macOS.
func openReadOnlyStateFile(path string) (*os.File, error) { return os.Open(path) }
