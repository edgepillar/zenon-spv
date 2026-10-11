package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const candidateExportEnvironment = "ZENON_SPV_PILOT_EXPORT_DIR"
const candidateBinaryLimit = 128 << 20

var candidateExportMu sync.Mutex

// Export the ordinary binary that the scenario will execute. Repeated builds
// must have identical bytes; never replace an earlier export with a new build.
func exportCandidateBinary(dir, command, path, expectedSHA string) error {
	return exportCandidateBinaryWithInput(dir, command, path, expectedSHA, openCandidateBinary)
}

func exportCandidateBinaryWithInput(dir, command, path, expectedSHA string, openInput func(string) (io.ReadCloser, int64, error)) error {
	candidateExportMu.Lock()
	defer candidateExportMu.Unlock()
	switch command {
	case "zenon-spv", "fetch-bundle", "derive-checkpoints", "derive-producer-schedule",
		"verify-mainnet-genesis", "consume-query-report", "observe-block":
	default:
		return errors.New("unsupported candidate command")
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil || !filepath.IsAbs(dir) || !dirInfo.IsDir() {
		return errors.New("candidate directory unavailable")
	}
	filename := command
	if runtime.GOOS == "windows" {
		filename += ".exe"
	}
	destination := filepath.Join(dir, filename)
	input, size, err := openInput(path)
	if err != nil {
		return errors.New("candidate binary cannot be read")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if os.IsExist(err) {
		if input.Close() != nil {
			return errors.New("candidate binary read failed")
		}
		return compareCandidateBinary(destination, expectedSHA, size)
	}
	if err != nil {
		_ = input.Close()
		return errors.New("candidate binary cannot be created")
	}
	if copyCandidateBinary(input, size, output, expectedSHA) != nil {
		_ = os.Remove(destination) // Only this newly created, incomplete copy.
		return errors.New("candidate binary copy failed")
	}
	return nil
}

func compareCandidateBinary(path, expectedSHA string, expectedSize int64) error {
	if expectedSize <= 0 || expectedSize > candidateBinaryLimit {
		return errors.New("candidate binary conflicts with an earlier export")
	}
	digest, size, err := candidateBinaryDigest(path)
	if err != nil || size != expectedSize || digest != expectedSHA {
		return errors.New("candidate binary conflicts with an earlier export")
	}
	return nil
}

func TestCandidateBinaryExport(t *testing.T) {
	raw := []byte("candidate binary bytes")
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	filename := "zenon-spv"
	if runtime.GOOS == "windows" {
		filename += ".exe"
	}
	setup := func(t *testing.T) (string, string) {
		t.Helper()
		root := t.TempDir()
		dir, path := filepath.Join(root, "export"), filepath.Join(root, "input")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir, path
	}
	t.Run("exact bytes and repeated export preserve file identity", func(t *testing.T) {
		dir, path := setup(t)
		if err := exportCandidateBinary(dir, "zenon-spv", path, digest); err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(dir, filename)
		before, err := os.Stat(destination)
		if err != nil {
			t.Fatal(err)
		}
		if err := exportCandidateBinary(dir, "zenon-spv", path, digest); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(destination)
		got, readErr := os.ReadFile(destination)
		if err != nil || readErr != nil || !bytes.Equal(got, raw) || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
			t.Fatal("repeated export replaced or changed tested bytes")
		}
	})
	for _, tc := range []struct {
		name string
		mode string
	}{
		{"wrong byte pin leaves no completed copy", "pin"},
		{"existing different bytes are preserved", "conflict"},
		{"existing directory is preserved", "directory"},
		{"empty source is refused", "empty"},
		{"oversized source is refused before copying", "oversize"},
		{"unknown command cannot choose an output path", "command"},
		{"relative output is refused", "relative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := setup(t)
			command, pin := "zenon-spv", digest
			destination := filepath.Join(dir, filename)
			switch tc.mode {
			case "pin":
				pin = strings.Repeat("a", 64)
			case "conflict":
				if err := os.WriteFile(destination, []byte("prior export"), 0o755); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(destination, 0o700); err != nil {
					t.Fatal(err)
				}
			case "empty", "oversize":
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o755)
				if err != nil {
					t.Fatal(err)
				}
				if tc.mode == "oversize" {
					if err := file.Truncate(candidateBinaryLimit + 1); err != nil {
						t.Fatal(err)
					}
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			case "command":
				command = "../PRIVATE_PATH"
			case "relative":
				dir = "."
			}
			if err := exportCandidateBinary(dir, command, path, pin); err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("invalid export accepted or private input disclosed")
			}
			switch tc.mode {
			case "conflict":
				got, err := os.ReadFile(destination)
				if err != nil || string(got) != "prior export" {
					t.Fatal("conflicting export was replaced")
				}
			case "directory":
				info, err := os.Stat(destination)
				if err != nil || !info.IsDir() {
					t.Fatal("existing directory was replaced")
				}
			default:
				if _, err := os.Lstat(destination); !os.IsNotExist(err) {
					t.Fatal("failed export left a completed copy")
				}
			}
		})
	}
	for _, mode := range []string{"read", "close", "grow", "shrink", "existing_close"} {
		t.Run("injected_"+mode+"_refusal_preserves_export_boundary", func(t *testing.T) {
			dir, path := setup(t)
			destination := filepath.Join(dir, filename)
			var before os.FileInfo
			if mode == "existing_close" {
				if err := os.WriteFile(destination, raw, 0o755); err != nil {
					t.Fatal(err)
				}
				var err error
				before, err = os.Stat(destination)
				if err != nil {
					t.Fatal(err)
				}
			}
			privateErr := errors.New("PRIVATE_INPUT_FAILURE")
			input := &candidateBinaryTestInput{reader: bytes.NewReader(raw)}
			switch mode {
			case "read":
				input.reader = candidateBinaryErrorReader{err: privateErr}
			case "close", "existing_close":
				input.closeErr = privateErr
			case "grow":
				input.reader = bytes.NewReader(append(bytes.Clone(raw), 0))
			case "shrink":
				input.reader = bytes.NewReader(raw[:len(raw)-1])
			}
			err := exportCandidateBinaryWithInput(dir, "zenon-spv", path, digest, func(string) (io.ReadCloser, int64, error) {
				return input, int64(len(raw)), nil
			})
			if err == nil || strings.Contains(err.Error(), "PRIVATE") || input.closed != 1 {
				t.Fatal("failed input was accepted, disclosed, or not closed exactly once")
			}
			if mode == "existing_close" {
				after, statErr := os.Stat(destination)
				got, readErr := os.ReadFile(destination)
				if statErr != nil || readErr != nil || !bytes.Equal(got, raw) || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
					t.Fatal("failed repeated export replaced the prior executable")
				}
			} else if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatal("failed new copy remained in the export directory")
			}
		})
	}
	t.Log("conformance-candidate-binary-export-controls {\"schema_version\":1,\"controls\":13,\"accepted_exports\":1,\"refusals\":12,\"failed_new_copies_removed\":5,\"injected_inputs_closed\":5,\"earlier_exports_preserved\":true}")
}
