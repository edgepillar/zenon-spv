//go:build darwin || linux

package verify

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

// Real no-writer FIFOs run in owned child processes: a regressed open cannot
// hang the suite. Replacement happens deterministically after the path stat.
func TestStateInputFIFOOpenIsBounded(t *testing.T) {
	const helperKey = "ZENON_SPV_STATE_INPUT_FIFO_HELPER"
	if mode := os.Getenv(helperKey); mode != "" {
		path := filepath.Join(t.TempDir(), "state.fifo")
		switch mode {
		case "selected":
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal("cannot create FIFO control")
			}
			state, err := LoadHeaderState(path)
			if !errors.Is(err, ErrStateFileNotRegular) || !state.Empty() {
				t.Fatal("selected FIFO reached state decoding")
			}
		case "replacement":
			if err := os.WriteFile(path, []byte("original regular input"), 0o600); err != nil {
				t.Fatal(err)
			}
			var opened *os.File
			file, info, err := openStateInput(path, func(name string) (*os.File, error) {
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(name, 0o600); err != nil {
					t.Fatal("cannot create replacement FIFO control")
				}
				var err error
				opened, err = openReadOnlyStateFile(name)
				return opened, err
			})
			if file != nil || info != nil || !errors.Is(err, ErrStateFileNotRegular) || opened == nil {
				t.Fatal("FIFO replacement bypassed the descriptor type check")
			}
			if _, err := opened.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("replacement FIFO descriptor was not closed")
			}
		default:
			t.Fatal("unknown FIFO control")
		}
		return
	}
	for _, mode := range []string{"selected", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStateInputFIFOOpenIsBounded$")
			cmd.Env = append(os.Environ(), helperKey+"="+mode)
			cmd.WaitDelay = time.Second
			if err := cmd.Run(); err != nil || ctx.Err() != nil {
				t.Fatal("real FIFO control did not refuse promptly; child killed and reaped on deadline")
			}
		})
	}
}
