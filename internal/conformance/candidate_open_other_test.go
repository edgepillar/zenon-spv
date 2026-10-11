//go:build !darwin && !linux

package conformance_test

import "os"

func openCandidateBinaryInput(path string) (*os.File, error) { return os.Open(path) }
