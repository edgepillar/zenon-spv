package statelock

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func supportedLockPlatform(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("OS writer locks are not implemented on this platform")
	}
}

func TestExclusiveStateLockPreservesFilesAndReusesInode(t *testing.T) {
	supportedLockPlatform(t)
	path := filepath.Join(t.TempDir(), "state.json")
	before := []byte("trusted state bytes")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	info, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatal("lock file has unexpectedly broad permissions")
	}
	if other, err := Acquire(path); other != nil || !errors.Is(err, ErrBusy) {
		_ = other.Close()
		t.Fatalf("second writer acquired the same state: %v", err)
	}
	differentPath := filepath.Join(filepath.Dir(path), "different-state.json")
	different, err := Acquire(differentPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := different.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(differentPath); !os.IsNotExist(err) {
		t.Fatal("locking a missing state created state bytes")
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if err := lock.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	reopened, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path + ".lock")
	if err != nil || !os.SameFile(info, after) {
		t.Fatal("release removed or replaced the lock namespace")
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, raw) {
		t.Fatal("locking altered trusted state bytes")
	}
}

func TestStateLockRejectsUnsafePathsWithoutPrivateDiagnostics(t *testing.T) {
	supportedLockPlatform(t)
	dir := t.TempDir()
	for _, path := range []string{"", dir, filepath.Join(dir, "PRIVATE_MISSING", "state.json"), filepath.Join(dir, "nul\x00state"), filepath.Join(dir, "reserved.LOCK")} {
		lock, err := Acquire(path)
		if err == nil || lock != nil {
			_ = lock.Close()
			t.Fatal("invalid state path acquired a lock")
		}
		if strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "PRIVATE_MISSING") {
			t.Fatal("lock error exposed a private path")
		}
	}
	for _, target := range []string{"state", "lock", "parent"} {
		t.Run(target+" symlink", func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "state.json")
			original := filepath.Join(root, "original")
			if target == "parent" {
				if err := os.Mkdir(original, 0o700); err != nil {
					t.Fatal(err)
				}
				alias := filepath.Join(root, "alias")
				if err := os.Symlink(original, alias); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				lock, err := Acquire(filepath.Join(original, "state.json"))
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = lock.Close() }()
				other, err := Acquire(filepath.Join(alias, "state.json"))
				if other != nil || !errors.Is(err, ErrBusy) {
					_ = other.Close()
					t.Fatal("parent alias bypassed the held lock")
				}
				return
			}
			marker := []byte("do not modify this symlink target")
			if err := os.WriteFile(original, marker, 0o600); err != nil {
				t.Fatal(err)
			}
			link := path
			if target == "lock" {
				link += ".lock"
			}
			if err := os.Symlink(original, link); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			lock, err := Acquire(path)
			if lock != nil || err == nil {
				_ = lock.Close()
				t.Fatal("final symlink acquired a writer lock")
			}
			raw, err := os.ReadFile(original)
			if err != nil || !bytes.Equal(raw, marker) {
				t.Fatal("symlink target was changed")
			}
		})
	}
}

func TestStateLockReleasedOnProcessExitOrKill(t *testing.T) {
	supportedLockPlatform(t)
	for _, kill := range []bool{false, true} {
		name := "exit"
		if kill {
			name = "kill"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, self, "-test.run=^TestStateLockHelperProcess$")
			cmd.Env = append(os.Environ(), "SPV_LOCK_HELPER_PATH="+path)
			cmd.WaitDelay = time.Second
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			line, err := bufio.NewReader(stdout).ReadString('\n')
			if err != nil || line != "locked\n" {
				t.Fatalf("child did not acquire the lock: %v", err)
			}
			if lock, err := Acquire(path); lock != nil || !errors.Is(err, ErrBusy) {
				_ = lock.Close()
				t.Fatal("child lock did not exclude the parent writer")
			}
			if kill {
				if err := cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
			} else if err := stdin.Close(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			if !kill && err != nil || ctx.Err() != nil {
				t.Fatalf("child did not terminate normally: %v", err)
			}
			lock, err := Acquire(path)
			// Windows may defer OS cleanup after an ungraceful exit. Keep
			// retries bounded and never delete the companion to force access.
			deadline := time.Now().Add(3 * time.Second)
			for runtime.GOOS == "windows" && errors.Is(err, ErrBusy) && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
				lock, err = Acquire(path)
			}
			if err != nil {
				t.Fatalf("OS did not release the child lock: %v", err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStateLockHelperProcess(t *testing.T) {
	path := os.Getenv("SPV_LOCK_HELPER_PATH")
	if path == "" {
		return
	}
	lock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(os.Stdout, "locked"); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	runtime.KeepAlive(lock)
	os.Exit(0) // Intentionally bypass Close: the OS must release the lock.
}
