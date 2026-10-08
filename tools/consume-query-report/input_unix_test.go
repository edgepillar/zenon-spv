//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Owned subprocesses bound a regressed open without hanging the test process.
// The replacement is deterministic: it occurs after Lstat and before open.
func TestConsumerInputFIFOOpenIsBounded(t *testing.T) {
	const helperKey = "ZENON_SPV_CONSUMER_INPUT_HELPER"
	if mode := os.Getenv(helperKey); mode != "" {
		path := filepath.Join(t.TempDir(), "input.json")
		if mode == "selected" {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal("cannot create selected FIFO control")
			}
			if raw, err := readInput(path, maxReportBytes); raw != nil || !errors.Is(err, os.ErrInvalid) {
				t.Fatal("selected FIFO reached report reading")
			}
			return
		}
		if err := os.WriteFile(path, []byte("ordinary input"), 0o600); err != nil {
			t.Fatal("cannot prepare replacement control")
		}
		var opened *os.File
		raw, err := readInputWithOpen(path, maxReportBytes, func(name string) (*os.File, error) {
			if err := os.Remove(name); err != nil {
				t.Fatal("cannot replace selected input")
			}
			switch mode {
			case "replacement":
				if err := syscall.Mkfifo(name, 0o600); err != nil {
					t.Fatal("cannot create replacement FIFO control")
				}
			case "symlink replacement":
				target := filepath.Join(t.TempDir(), "target.json")
				if err := os.WriteFile(target, []byte("replacement input"), 0o600); err != nil {
					t.Fatal("cannot prepare symlink target")
				}
				if err := os.Symlink(target, name); err != nil {
					t.Fatal("cannot create replacement symlink control")
				}
			default:
				t.Fatal("unknown input control")
			}
			var err error
			opened, err = openReadOnlyInput(name)
			return opened, err
		})
		if raw != nil || err == nil {
			t.Fatal("replacement input was consumed")
		}
		if mode == "replacement" {
			if !errors.Is(err, os.ErrInvalid) || opened == nil {
				t.Fatal("replacement FIFO bypassed descriptor validation")
			}
			if _, err := opened.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("replacement FIFO descriptor was not closed")
			}
		} else if opened != nil {
			t.Fatal("final-component symlink was opened")
		}
		return
	}
	for _, mode := range []string{"selected", "replacement", "symlink replacement"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConsumerInputFIFOOpenIsBounded$")
			cmd.Env = append(os.Environ(), helperKey+"="+mode)
			cmd.WaitDelay = time.Second
			if err := cmd.Run(); err != nil || ctx.Err() != nil {
				t.Fatal("input control did not refuse promptly; child killed and reaped on deadline")
			}
		})
	}
}
