package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/0x3639/zenon-spv/internal/verify"
)

// Keep filesystem paths out of ordinary diagnostics while preserving causes
// for callers. A directory-sync error happens after the replacement is visible.
type scheduleOutputError struct {
	stage   string
	cause   error
	visible bool
}

func (e *scheduleOutputError) Error() string {
	message := "schedule output: " + e.stage + " failed"
	if e.visible {
		message += "; new output is visible but durability is unconfirmed"
	}
	return message
}

func (e *scheduleOutputError) Unwrap() error { return e.cause }

func resolveScheduleOutput(path string) (string, error) {
	// Resolve filesystem parent traversal before joining the basename. Lexical
	// cleaning first could redirect a symlink/../file to a different directory.
	parent, name := filepath.Split(path)
	if name == "" {
		return "", errors.New("schedule output must name a file")
	}
	if parent == "" {
		parent = "."
	}
	parent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", &scheduleOutputError{stage: "resolve directory", cause: err}
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return "", &scheduleOutputError{stage: "resolve directory", cause: err}
	}
	path = filepath.Join(parent, name)
	if err := checkScheduleOutput(path); err != nil {
		return "", err
	}
	return path, nil
}

func checkScheduleOutput(path string) error {
	info, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return &scheduleOutputError{stage: "inspect destination", cause: err}
	}
	if info != nil && !info.Mode().IsRegular() {
		return errors.New("schedule output must be a regular file, not a symlink or special file")
	}
	return nil
}

type scheduleOutputFile interface {
	io.WriteCloser
	Name() string
	Sync() error
}

type scheduleOutputIO struct {
	createTemp func(string) (scheduleOutputFile, error)
	remove     func(string) error
	rename     func(string, string) error
	syncDir    func(string) error
}

func defaultScheduleOutputIO() scheduleOutputIO {
	return scheduleOutputIO{
		createTemp: func(dir string) (scheduleOutputFile, error) { return os.CreateTemp(dir, ".spv-schedule-*") },
		remove:     os.Remove,
		rename:     os.Rename,
		syncDir: func(dir string) error {
			if runtime.GOOS == "windows" {
				return nil // Directory durability remains best-effort on Windows.
			}
			f, err := os.Open(dir)
			if err != nil {
				return err
			}
			if err := f.Sync(); err != nil {
				_ = f.Close()
				return err
			}
			return f.Close()
		},
	}
}

// publishScheduleOutput requires an already resolved destination in a trusted
// directory. It stages private bytes beside the destination before replacement.
// This is not a writer lock; callers must coordinate concurrent exporters.
func publishScheduleOutput(path string, data []byte, fs scheduleOutputIO) error {
	if len(data) > verify.MaxProducerScheduleFileBytes {
		return verify.ErrProducerScheduleTooLarge
	}
	if err := checkScheduleOutput(path); err != nil {
		return err
	}
	f, err := fs.createTemp(filepath.Dir(path))
	if err != nil {
		return &scheduleOutputError{stage: "create staged file", cause: err}
	}
	staged := f.Name()
	defer func() {
		if staged != "" {
			_ = fs.remove(staged)
		}
	}()
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		_ = f.Close()
		return &scheduleOutputError{stage: "write staged file", cause: err}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return &scheduleOutputError{stage: "sync staged file", cause: err}
	}
	if err := f.Close(); err != nil {
		return &scheduleOutputError{stage: "close staged file", cause: err}
	}
	if err := checkScheduleOutput(path); err != nil {
		return err
	}
	if err := fs.rename(staged, path); err != nil {
		return &scheduleOutputError{stage: "replace destination", cause: err}
	}
	staged = ""
	if err := fs.syncDir(filepath.Dir(path)); err != nil {
		return &scheduleOutputError{stage: "sync directory", cause: err, visible: true}
	}
	return nil
}
