package verify

import (
	"errors"
	"os"
)

// ErrStateFileNotRegular refuses stream/device inputs without parsing them as
// saved state. File type and size checks do not authenticate state provenance.
var ErrStateFileNotRegular = errors.New("state input must be a regular file")

// Check before opening: a FIFO without a writer can block even its first open.
// Check the descriptor again: the pathname can change after the initial stat.
// Readers retain regular-file symlink support; writer locking has its own
// stricter path policy. The open callback makes replacement/cleanup testable
// without changing global process behavior.
func openStateInput(path string, openFile func(string) (*os.File, error)) (*os.File, os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, ErrStateFileNotRegular
	}
	if info.Size() > MaxStateFileBytes {
		return nil, nil, ErrStateFileTooLarge
	}
	f, err := openFile(path)
	if err != nil {
		return nil, nil, err
	}
	info, err = f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = ErrStateFileNotRegular
	}
	if err == nil && info.Size() > MaxStateFileBytes {
		err = ErrStateFileTooLarge
	}
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, info, nil
}
