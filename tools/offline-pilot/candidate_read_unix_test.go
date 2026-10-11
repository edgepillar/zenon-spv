//go:build darwin || linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCandidateFIFOHelper(t *testing.T) {
	if os.Getenv("SPV_CANDIDATE_FIFO_HELPER") != "1" {
		return
	}
	mode, path := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	open := openSourceInput
	if mode == "replacement" {
		open = func(name string) (*os.File, error) {
			if os.Remove(name) != nil || syscall.Mkfifo(name, 0600) != nil {
				os.Exit(71)
			}
			return openSourceInput(name)
		}
	} else if mode != "selected" || syscall.Mkfifo(path, 0600) != nil {
		os.Exit(71)
	}
	if f, _, err := checkedCandidateInput(path, open); err == nil || f != nil {
		os.Exit(72)
	}
	os.Exit(0)
}

func TestCandidateNonregularOpenBoundaries(t *testing.T) {
	for _, mode := range []string{"selected", "replacement"} {
		t.Run(mode+"_FIFO", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "candidate")
			if mode == "replacement" && os.WriteFile(path, []byte("binary"), 0600) != nil {
				t.Fatal("cannot prepare candidate replacement")
			}
			self, err := os.Executable()
			if err != nil {
				t.Fatal("cannot locate candidate native helper")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, self, "-test.run=^TestCandidateFIFOHelper$", "--", mode, path)
			cmd.Env = append(os.Environ(), "SPV_CANDIDATE_FIFO_HELPER=1")
			cmd.WaitDelay = time.Second
			if err := cmd.Run(); err != nil || ctx.Err() != nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 0 {
				t.Fatal("candidate FIFO refusal failed or waited for a writer")
			}
			t.Logf("offline-pilot-candidate-FIFO-child {\"mode\":%q,\"actual_child_exit\":%d,\"deadline_exceeded\":false}", mode, cmd.ProcessState.ExitCode())
		})
		t.Run(mode+"_symlink", func(t *testing.T) {
			dir := t.TempDir()
			path, target := filepath.Join(dir, "candidate"), filepath.Join(dir, "target")
			if os.WriteFile(target, []byte("binary"), 0600) != nil {
				t.Fatal("cannot prepare candidate link target")
			}
			open := openSourceInput
			if mode == "selected" {
				if os.Symlink(target, path) != nil {
					t.Fatal("cannot prepare selected link")
				}
			} else {
				if os.WriteFile(path, []byte("binary"), 0600) != nil {
					t.Fatal("cannot prepare replaced link")
				}
				open = func(name string) (*os.File, error) {
					if os.Remove(name) != nil || os.Symlink(target, name) != nil {
						return nil, os.ErrInvalid
					}
					return openSourceInput(name)
				}
			}
			if f, _, err := checkedCandidateInput(path, open); err == nil || f != nil {
				t.Fatal("candidate symlink was followed")
			}
		})
	}
	t.Log("offline-pilot-candidate-nonregular-controls {\"schema_version\":1,\"refusals\":4,\"joined_native_helpers\":2,\"final_symlink_followed\":false}")
}
