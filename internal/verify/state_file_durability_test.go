package verify

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestSaveHeaderState_ParentOpenFailureIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("parent-directory sync is not supported by this Windows path")
	}
	state := sampleState(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	openErr := errors.New("injected directory open failure")
	err := saveHeaderState(path, state, func(got string) (*os.File, error) {
		if got != dir {
			t.Errorf("directory = %q, want parent directory", got)
		}
		return nil, openErr
	})
	if !errors.Is(err, openErr) {
		t.Fatalf("save error = %v, want wrapped directory error", err)
	}
	// Rename has already happened. An error means durability is unknown,
	// not that the previous file is guaranteed to remain on disk.
	loaded, loadErr := LoadHeaderState(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if !reflect.DeepEqual(loaded, state) {
		t.Error("renamed file differs from candidate state")
	}
}

func TestSaveHeaderState_ParentSyncFailureIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("parent-directory sync is not supported by this Windows path")
	}
	dir := t.TempDir()
	closedDir, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := closedDir.Close(); err != nil {
		t.Fatal(err)
	}
	err = saveHeaderState(filepath.Join(dir, "state.json"), sampleState(t),
		func(string) (*os.File, error) { return closedDir, nil })
	if !errors.Is(err, os.ErrClosed) || !strings.Contains(err.Error(), "sync parent directory") {
		t.Fatalf("save error = %v, want parent sync error", err)
	}
}
