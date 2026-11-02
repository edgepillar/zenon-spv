//go:build !darwin && !linux

// SPDX-License-Identifier: MIT

package main

import "os"

// Shared checks require a regular, unchanged file before and after opening.
// Native FIFO replacement behavior is qualified only on Linux/macOS.
func openExperimentalCLIFile(path string) (*os.File, error) { return os.Open(path) }
