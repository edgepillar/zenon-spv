//go:build darwin || linux

// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Hosted complete-suite control. Keep these intentionally nonregular fixtures
// outside managed local qualification scratch; the task observer refuses them.
func TestExperimentalBatchInputNonregularUnix(t *testing.T) {
	dir := t.TempDir()
	regular, fifo, alias := filepath.Join(dir, "regular"), filepath.Join(dir, "fifo"), filepath.Join(dir, "alias")
	if os.WriteFile(regular, []byte("{}"), 0600) != nil || syscall.Mkfifo(fifo, 0600) != nil || os.Symlink(regular, alias) != nil {
		t.Fatal("fixture")
	}
	for _, path := range []string{fifo, alias} {
		if raw, err := readExperimentalCLIFile(path, 32, func(string) (*os.File, error) { t.Fatal("nonregular input reached open"); return nil, nil }); err == nil || raw != nil {
			t.Fatal("nonregular input accepted")
		}
	}
	type replacementResult struct {
		fixtureErr error
		accepted   bool
	}
	done := make(chan replacementResult, 1)
	go func() {
		var fixtureErr error
		raw, err := readExperimentalCLIFile(regular, 32, func(path string) (*os.File, error) {
			if fixtureErr = os.Remove(path); fixtureErr == nil {
				fixtureErr = syscall.Mkfifo(path, 0600)
			}
			if fixtureErr != nil {
				return nil, fixtureErr
			}
			return openExperimentalCLIFile(path)
		})
		done <- replacementResult{fixtureErr, err == nil || raw != nil}
	}()
	select {
	case result := <-done:
		if result.fixtureErr != nil {
			t.Fatal("replacement fixture", result.fixtureErr)
		}
		if result.accepted {
			t.Fatal("FIFO replacement accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO replacement waited for a writer")
	}
}
