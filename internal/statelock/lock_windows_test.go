package statelock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsStateNameNamespace(t *testing.T) {
	for _, name := range []string{"state.json", "trusted-state", "STATE.JSON", ".state", "COM10.json", "COM1-state.json", "archive.COM1"} {
		if !stateNameSupported(name) {
			t.Fatalf("ordinary filename refused: %q", name)
		}
	}
	for _, name := range []string{"state.json.", "state.json ", "state.lock.", "STATE~1.JSON", "state.json:stream", "NUL", "CON", "COM1.txt"} {
		if stateNameSupported(name) {
			t.Fatalf("ambiguous filename accepted: %q", name)
		}
	}
}

func TestWindowsDeviceNamesRefusedBeforeOpeningCompanion(t *testing.T) {
	for _, device := range []string{"CON", "PRN", "AUX", "NUL", "COM1", "COM9", "LPT1", "LPT9", "COM\u00b2", "LPT\u00b9", "CONIN$", "CONOUT$"} {
		for _, suffix := range []string{"", ".json", ".backup.json", " .json"} {
			for _, name := range []string{device + suffix, strings.ToLower(device) + suffix} {
				t.Run(name, func(t *testing.T) {
					dir := t.TempDir()
					lock, err := Acquire(filepath.Join(dir, name))
					if lock != nil || !errors.Is(err, ErrInvalidPath) {
						_ = lock.Close()
						t.Fatalf("device-like state name reached filesystem operations: %v", err)
					}
					entries, err := os.ReadDir(dir)
					if err != nil || len(entries) != 0 {
						t.Fatal("refused device name left files behind")
					}
				})
			}
		}
	}
}
