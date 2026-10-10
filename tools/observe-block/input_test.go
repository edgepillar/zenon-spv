package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var preflightRoles = []string{"binary", "expectations"}

func checkPreflightRole(role, path string, selected []byte, openFile func(string) (*os.File, error)) ([]byte, bool) {
	if role == "binary" {
		h := sha256.Sum256(selected)
		return nil, binaryMatchesWithOpen(path, hex.EncodeToString(h[:]), openFile)
	}
	return readExpectationsWithOpen(path, openFile)
}

func preflightLimit(role string) int64 {
	if role == "binary" {
		return maxBinaryBytes
	}
	return maxExpectationsBytes
}

func writeSparsePreflight(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal("cannot create size control")
	}
	err = f.Truncate(size)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal("cannot prepare size control")
	}
}

func TestObserverPreflightInputs(t *testing.T) {
	for _, role := range preflightRoles {
		for _, mode := range []string{"regular", "empty", "selected-directory", "selected-missing", "selected-too-large", "replacement-regular", "replacement-directory", "replacement-too-large", "open-error", "closed-descriptor"} {
			t.Run(role+"/"+mode, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "PRIVATE_INPUT")
				selected := []byte("selected input")
				if mode == "empty" {
					selected = nil
				}
				if err := os.WriteFile(path, selected, 0o600); err != nil {
					t.Fatal("cannot prepare input control")
				}
				switch mode {
				case "selected-directory", "selected-missing":
					if os.Remove(path) != nil {
						t.Fatal("cannot prepare unavailable control")
					}
					if mode == "selected-directory" && os.Mkdir(path, 0o700) != nil {
						t.Fatal("cannot prepare directory control")
					}
				case "selected-too-large":
					writeSparsePreflight(t, path, preflightLimit(role)+1)
				}
				var opened *os.File
				called := 0
				replacement := []byte("different ordinary input")
				raw, ok := checkPreflightRole(role, path, selected, func(name string) (*os.File, error) {
					called++
					if mode == "open-error" {
						return nil, os.ErrPermission
					}
					switch mode {
					case "replacement-regular", "replacement-directory", "replacement-too-large":
						if os.Remove(name) != nil {
							t.Fatal("cannot replace selected input")
						}
						switch mode {
						case "replacement-regular":
							if os.WriteFile(name, replacement, 0o600) != nil {
								t.Fatal("cannot prepare replacement bytes")
							}
						case "replacement-directory":
							if os.Mkdir(name, 0o700) != nil {
								t.Fatal("cannot prepare replacement directory")
							}
						case "replacement-too-large":
							writeSparsePreflight(t, name, preflightLimit(role)+1)
						}
					}
					var err error
					opened, err = openPreflightInput(name)
					if mode == "closed-descriptor" && err == nil {
						err = opened.Close()
					}
					return opened, err
				})
				want := mode == "regular" || mode == "empty" || role == "expectations" && mode == "replacement-regular"
				if ok != want {
					t.Fatal("input result differs from selected boundary")
				}
				if role == "expectations" && want {
					wantRaw := selected
					if mode == "replacement-regular" {
						wantRaw = replacement
					}
					if !bytes.Equal(raw, wantRaw) {
						t.Fatal("expectations snapshot changed opened bytes")
					}
				}
				wantCalls := 1
				if mode == "selected-directory" || mode == "selected-missing" || mode == "selected-too-large" {
					wantCalls = 0
				}
				if called != wantCalls {
					t.Fatal("selected invalid input reached open or valid input skipped open")
				}
				if opened != nil {
					// Windows Stat delegates to the native handle API and does not
					// normalize its closed-handle error to os.ErrClosed. A repeated
					// Close checks the same ownership condition on every platform.
					if err := opened.Close(); !errors.Is(err, os.ErrClosed) {
						t.Fatal("input descriptor survived preflight consumption")
					}
				}
			})
		}
	}
}
