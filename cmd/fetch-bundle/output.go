package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type outputDestination struct {
	label string
	path  string // Canonical parent plus basename, or "-" for stdout.
}

func resolveOutputDestinations(bundle, checkpoint string) ([]outputDestination, error) {
	outputs := []outputDestination{{label: "bundle", path: bundle}}
	if checkpoint != "" {
		outputs = append(outputs, outputDestination{label: "checkpoint", path: checkpoint})
	}
	for i := range outputs {
		o := &outputs[i]
		if o.path == "-" {
			continue
		}
		if o.path == "" {
			return nil, fmt.Errorf("%s output path must not be empty", o.label)
		}
		// Split without cleaning first: symlink/../file must retain the
		// filesystem's parent traversal, not a different lexical destination.
		parent, name := filepath.Split(o.path)
		if name == "" {
			return nil, fmt.Errorf("%s output must name a file", o.label)
		}
		if parent == "" {
			parent = "."
		}
		parent, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return nil, fmt.Errorf("resolve %s output directory: %w", o.label, err)
		}
		parent, err = filepath.Abs(parent)
		if err != nil {
			return nil, fmt.Errorf("resolve %s output directory: %w", o.label, err)
		}
		o.path = filepath.Join(parent, name)
	}
	if err := validateOutputDestinations(outputs); err != nil {
		return nil, err
	}
	return outputs, nil
}

func validateOutputDestinations(outputs []outputDestination) error {
	infos := make([]os.FileInfo, len(outputs))
	for i, o := range outputs {
		if o.path != "-" {
			info, err := os.Lstat(o.path)
			if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("inspect %s output: %w", o.label, err)
			}
			if info != nil && !info.Mode().IsRegular() {
				return fmt.Errorf("%s output must be a regular file, not a symlink or special file", o.label)
			}
			infos[i] = info
		}
		for j := 0; j < i; j++ {
			// Conservatively refuse case-only aliases even on case-sensitive hosts.
			if strings.EqualFold(o.path, outputs[j].path) || (infos[i] != nil && infos[j] != nil && os.SameFile(infos[i], infos[j])) {
				return errors.New("bundle and checkpoint must have distinct destinations; stdout may be used only once")
			}
		}
	}
	return nil
}

type outputFile interface {
	io.WriteCloser
	Name() string
	Sync() error
}

// Injectable filesystem boundaries keep failure-ordering tests deterministic.
type outputIO struct {
	createTemp func(string) (outputFile, error)
	remove     func(string) error
	rename     func(string, string) error
	syncDir    func(string) error
}

func defaultOutputIO() outputIO {
	return outputIO{
		createTemp: func(dir string) (outputFile, error) { return os.CreateTemp(dir, ".spv-output-*") },
		remove:     os.Remove,
		rename:     os.Rename,
		syncDir: func(dir string) error {
			// Windows does not provide the same directory-fsync/rename contract.
			if runtime.GOOS == "windows" {
				return nil
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

// publishOutputs stages every file before replacing any destination. Individual
// renames are atomic on Unix filesystems, but two files and stdout cannot form
// one atomic transaction. After publication begins, any error may leave some
// new outputs visible; callers must report failure and never retry implicitly.
func publishOutputs(outputs []outputDestination, data [][]byte, stdout io.Writer, fs outputIO) error {
	if len(outputs) != len(data) {
		return errors.New("internal output count mismatch")
	}
	if err := validateOutputDestinations(outputs); err != nil {
		return err
	}
	staged := make([]string, len(outputs))
	defer func() {
		for _, path := range staged {
			if path != "" {
				_ = fs.remove(path)
			}
		}
	}()
	for i, o := range outputs {
		if o.path == "-" {
			continue
		}
		f, err := fs.createTemp(filepath.Dir(o.path))
		if err != nil {
			return fmt.Errorf("stage %s output: %w", o.label, err)
		}
		staged[i] = f.Name()
		if err := writeComplete(f, data[i]); err != nil {
			_ = f.Close()
			return fmt.Errorf("stage %s output: %w", o.label, err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return fmt.Errorf("sync staged %s output: %w", o.label, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close staged %s output: %w", o.label, err)
		}
	}
	// Recheck after staging to catch intervening aliases and non-regular files.
	// Output directories must still be trusted against concurrent replacement.
	if err := validateOutputDestinations(outputs); err != nil {
		return err
	}
	for i, o := range outputs {
		if o.path == "-" {
			continue
		}
		if i > 0 {
			// A newly created file can expose an alias under filesystem-specific
			// name normalization that was not observable when both paths were absent.
			if err := validateOutputDestinations(outputs); err != nil {
				return fmt.Errorf("recheck %s output; some outputs may already be visible: %w", o.label, err)
			}
		}
		if err := fs.rename(staged[i], o.path); err != nil {
			return fmt.Errorf("publish %s output; some outputs may already be visible: %w", o.label, err)
		}
		staged[i] = ""
		if err := fs.syncDir(filepath.Dir(o.path)); err != nil {
			return fmt.Errorf("sync %s output directory; new output is visible but durability is unconfirmed: %w", o.label, err)
		}
	}
	// Publish all file destinations before emitting the one permitted stdout.
	for i, o := range outputs {
		if o.path == "-" {
			if err := writeComplete(stdout, data[i]); err != nil {
				return fmt.Errorf("write %s to stdout; files or partial stdout may already be visible: %w", o.label, err)
			}
		}
	}
	return nil
}

func writeComplete(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}
