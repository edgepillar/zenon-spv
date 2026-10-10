//go:build !darwin && !linux

package main

import "os"

// Descriptor checks remain common. Native FIFO replacement and final-component
// no-follow controls are limited to Linux/macOS, as in the report consumer.
func openPreflightInput(path string) (*os.File, error) { return os.Open(path) }
