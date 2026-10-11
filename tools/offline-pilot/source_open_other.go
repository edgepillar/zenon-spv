//go:build !darwin && !linux

package main

import "os"

func openSourceInput(path string) (*os.File, error) { return os.Open(path) }
