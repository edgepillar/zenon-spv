//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Replace the selected pathname exactly after Lstat and before open. Each
// owned subprocess has its own deadline, so a regressed FIFO open is reaped
// without hanging the test process. No timing race or external writer is used.
func TestObserverPreflightReplacements(t *testing.T) {
	const helperKey = "ZENON_SPV_OBSERVER_PREFLIGHT_HELPER"
	const directoryKey = "ZENON_SPV_OBSERVER_PREFLIGHT_DIRECTORY"
	if control := os.Getenv(helperKey); control != "" {
		parts := strings.Split(control, "/")
		if len(parts) != 2 || (parts[0] != "binary" && parts[0] != "expectations") {
			t.Fatal("unknown preflight control")
		}
		role, mode := parts[0], parts[1]
		// The supervising test owns this directory and cleans it after reap,
		// including when a regressed child is killed before its own cleanup.
		directory := os.Getenv(directoryKey)
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatal("missing owned preflight directory")
		}
		path := filepath.Join(directory, "PRIVATE_INPUT")
		selected := []byte("selected input")
		if mode == "selected-fifo" {
			if syscall.Mkfifo(path, 0o600) != nil {
				t.Fatal("cannot prepare selected FIFO")
			}
		} else if os.WriteFile(path, selected, 0o600) != nil {
			t.Fatal("cannot prepare selected input")
		}
		var opened *os.File
		called := 0
		_, ok := checkPreflightRole(role, path, selected, func(name string) (*os.File, error) {
			called++
			if os.Remove(name) != nil {
				t.Fatal("cannot replace selected input")
			}
			switch mode {
			case "replacement-fifo":
				if syscall.Mkfifo(name, 0o600) != nil {
					t.Fatal("cannot prepare replacement FIFO")
				}
			case "replacement-symlink":
				target := filepath.Join(directory, "target")
				if os.WriteFile(target, selected, 0o600) != nil || os.Symlink(target, name) != nil {
					t.Fatal("cannot prepare replacement symlink")
				}
			default:
				t.Fatal("selected nonregular input reached open")
			}
			var err error
			opened, err = openPreflightInput(name)
			return opened, err
		})
		if ok {
			t.Fatal("replacement input was consumed")
		}
		if mode == "selected-fifo" {
			if called != 0 || opened != nil {
				t.Fatal("selected FIFO reached descriptor acquisition")
			}
		} else if called != 1 {
			t.Fatal("replacement control missed the selected open boundary")
		} else if mode == "replacement-fifo" {
			if opened == nil {
				t.Fatal("replacement FIFO did not reach descriptor validation")
			}
			if err := opened.Close(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("replacement FIFO descriptor was not closed")
			}
		} else if opened != nil {
			t.Fatal("final-component symlink was opened")
		}
		return
	}
	for _, role := range preflightRoles {
		for _, mode := range []string{"selected-fifo", "replacement-fifo", "replacement-symlink"} {
			t.Run(role+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestObserverPreflightReplacements$")
				cmd.Env = append(os.Environ(), helperKey+"="+role+"/"+mode, directoryKey+"="+t.TempDir(), "GORACE=atexit_sleep_ms=0")
				cmd.WaitDelay = time.Second
				if err := cmd.Run(); err != nil || ctx.Err() != nil {
					t.Fatal("preflight control did not refuse; owned child killed and reaped on deadline if needed")
				}
			})
		}
	}
}
