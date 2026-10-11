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

func TestSourceFIFOHelper(t *testing.T) {
	if os.Getenv("SPV_SOURCE_FIFO_HELPER") != "1" {
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
	if f, _, err := checkedSourceInput(path, maxSourceBytes, open); err == nil || f != nil {
		os.Exit(72)
	}
	os.Exit(0)
}

func TestSourceNonregularOpenBoundaries(t *testing.T) {
	for _, mode := range []string{"selected", "replacement"} {
		t.Run(mode+" FIFO", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "member.go")
			if mode == "replacement" && os.WriteFile(path, []byte("abc"), 0600) != nil {
				t.Fatal("cannot prepare replacement input")
			}
			self, err := os.Executable()
			if err != nil {
				t.Fatal("cannot locate native helper")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, self, "-test.run=^TestSourceFIFOHelper$", "--", mode, path)
			cmd.Env = append(os.Environ(), "SPV_SOURCE_FIFO_HELPER=1")
			cmd.WaitDelay = time.Second
			if err := cmd.Run(); err != nil || ctx.Err() != nil {
				t.Fatal("source FIFO refusal failed or waited for a writer")
			}
		})
	}
	dir := t.TempDir()
	path, target := filepath.Join(dir, "member.go"), filepath.Join(dir, "target")
	if os.WriteFile(path, []byte("abc"), 0600) != nil || os.WriteFile(target, []byte("abc"), 0600) != nil {
		t.Fatal("cannot prepare symlink replacement")
	}
	f, _, err := checkedSourceInput(path, 3, func(name string) (*os.File, error) {
		if os.Remove(name) != nil || os.Symlink(target, name) != nil {
			return nil, os.ErrInvalid
		}
		return openSourceInput(name)
	})
	if err == nil || f != nil {
		t.Fatal("source final-component symlink replacement was followed")
	}
	t.Log("offline-pilot-source-nonregular-controls {\"schema_version\":1,\"refusals\":3,\"joined_native_helpers\":2,\"final_symlink_followed\":false}")
}
