//go:build darwin || linux

package conformance_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCandidateBinaryFIFOHelper(t *testing.T) {
	if os.Getenv("SPV_CANDIDATE_BINARY_FIFO_HELPER") != "1" {
		return
	}
	mode, path := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	open := openCandidateBinaryInput
	if mode == "replacement" {
		open = func(name string) (*os.File, error) {
			if os.Remove(name) != nil || syscall.Mkfifo(name, 0o600) != nil {
				os.Exit(71)
			}
			return openCandidateBinaryInput(name)
		}
	} else if mode != "selected" || syscall.Mkfifo(path, 0o600) != nil {
		os.Exit(71)
	}
	file, _, err := checkedCandidateBinaryInput(path, open)
	if file != nil {
		_ = file.Close()
	}
	if err == nil || file != nil {
		os.Exit(72)
	}
	os.Exit(0)
}

func TestCandidateBinaryNonregularOpenBoundaries(t *testing.T) {
	for _, mode := range []string{"selected", "replacement"} {
		t.Run(mode+"_FIFO", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "candidate")
			if mode == "replacement" && os.WriteFile(path, []byte("binary"), 0o600) != nil {
				t.Fatal("cannot prepare candidate replacement")
			}
			self, err := os.Executable()
			if err != nil {
				t.Fatal("cannot locate candidate binary native helper")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, self, "-test.run=^TestCandidateBinaryFIFOHelper$", "--", mode, path)
			cmd.Env = append(os.Environ(), "SPV_CANDIDATE_BINARY_FIFO_HELPER=1")
			cmd.WaitDelay = time.Second
			if err := cmd.Run(); err != nil || ctx.Err() != nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 0 {
				t.Fatal("candidate binary FIFO refusal failed or waited for a writer")
			}
			t.Logf("conformance-candidate-binary-FIFO-child {\"mode\":%q,\"actual_child_exit\":%d,\"deadline_exceeded\":false}", mode, cmd.ProcessState.ExitCode())
		})
		t.Run(mode+"_symlink", func(t *testing.T) {
			root := t.TempDir()
			path, target := filepath.Join(root, "candidate"), filepath.Join(root, "target")
			if os.WriteFile(target, []byte("binary"), 0o600) != nil {
				t.Fatal("cannot prepare candidate binary link target")
			}
			open := openCandidateBinaryInput
			if mode == "selected" {
				if os.Symlink(target, path) != nil {
					t.Fatal("cannot prepare selected link")
				}
			} else {
				if os.WriteFile(path, []byte("binary"), 0o600) != nil {
					t.Fatal("cannot prepare replaced link")
				}
				open = func(name string) (*os.File, error) {
					if os.Remove(name) != nil || os.Symlink(target, name) != nil {
						return nil, os.ErrInvalid
					}
					return openCandidateBinaryInput(name)
				}
			}
			file, _, err := checkedCandidateBinaryInput(path, open)
			if file != nil {
				_ = file.Close()
			}
			if err == nil || file != nil {
				t.Fatal("candidate binary symlink was followed")
			}
		})
	}
	t.Log("conformance-candidate-binary-nonregular-controls {\"schema_version\":1,\"refusals\":4,\"joined_native_helpers\":2,\"final_symlink_followed\":false}")
}
