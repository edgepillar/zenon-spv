// Package statelock coordinates cooperating writers of a trusted state path.
// It does not authenticate local files or protect against directory tampering.
package statelock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	ErrBusy        = errors.New("state file already has an active writer")
	ErrInvalidPath = errors.New("state and lock paths must be regular files; .lock state names are reserved")
	ErrUnsupported = errors.New("state writer locking is unsupported on this platform")
)

// operationError retains the cause for inspection without disclosing local
// paths in ordinary diagnostics.
type operationError struct{ cause error }

func (e *operationError) Error() string { return "state writer lock unavailable" }
func (e *operationError) Unwrap() error { return e.cause }

// Lock owns an OS-released advisory lock on a persistent companion file.
// Do not copy it, remove the companion file, or replace parent directories.
// Close is idempotent and safe to call concurrently.
type Lock struct {
	mu   sync.Mutex
	file *os.File
}

// Acquire takes an exclusive, nonblocking lock before loading mutable state.
// A missing state file is allowed; its parent directory must exist. Parent
// symlinks are resolved for the lock namespace. Final state/lock symlinks and
// nonregular files are refused, and .lock state names are reserved. No state
// bytes are read or written here.
//
// The companion <state-path>.lock is never truncated or removed. Deleting it
// while another process holds it would create a second lock namespace and
// defeat mutual exclusion. An unlocked leftover file is harmless after exit
// or a crash: lock ownership belongs to the OS, not the file's existence.
func Acquire(path string) (*Lock, error) {
	if path == "" {
		return nil, ErrInvalidPath
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, &operationError{err}
	}
	// Reserve the companion namespace: another state writer must never
	// atomically replace this writer's lock file as its own state payload.
	name := filepath.Base(abs)
	if strings.HasSuffix(strings.ToLower(name), ".lock") || !stateNameSupported(name) {
		return nil, ErrInvalidPath
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, &operationError{err}
	}
	canonical := filepath.Join(parent, filepath.Base(abs))
	if info, err := os.Lstat(canonical); err == nil {
		if !info.Mode().IsRegular() {
			return nil, ErrInvalidPath
		}
	} else if !os.IsNotExist(err) {
		return nil, &operationError{err}
	}
	lockPath := canonical + ".lock"
	f, err := openLockFile(lockPath)
	if err != nil {
		return nil, &operationError{err}
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		if err != nil {
			return nil, &operationError{err}
		}
		return nil, ErrInvalidPath
	}
	if err := tryLock(f); err != nil {
		_ = f.Close()
		if errors.Is(err, ErrBusy) {
			return nil, ErrBusy
		}
		return nil, &operationError{err}
	}
	current, err := os.Lstat(lockPath)
	if err != nil || !os.SameFile(info, current) || !current.Mode().IsRegular() {
		_ = unlockFile(f)
		_ = f.Close()
		return nil, ErrInvalidPath
	}
	return &Lock{file: f}, nil
}

// Close explicitly unlocks and closes the handle. The file remains present.
func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil
	unlockErr := unlockFile(f)
	if err := errors.Join(unlockErr, f.Close()); err != nil {
		return &operationError{err}
	}
	return nil
}
