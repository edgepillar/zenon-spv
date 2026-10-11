package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type candidateReadFixture struct {
	sourceReader
	closeErr error
	closed   bool
}

func (r *candidateReadFixture) Close() error { r.closed = true; return r.closeErr }

func TestCandidateReadContract(t *testing.T) {
	readFailure, closeFailure := errors.New("PRIVATE_READ_FAILURE"), errors.New("PRIVATE_CLOSE_FAILURE")
	for _, tc := range []struct {
		name          string
		raw           string
		size          int64
		step          int
		readErr       error
		closeErr      error
		dataError, ok bool
	}{
		{"complete", "binary\x00", 7, 32, io.EOF, nil, false, true},
		{"complete_with_EOF", "binary\x00", 7, 32, io.EOF, nil, true, true},
		{"short_reads", "binary\x00", 7, 1, io.EOF, nil, false, true},
		{"empty", "", 0, 1, io.EOF, nil, false, false},
		{"negative", "", -1, 1, io.EOF, nil, false, false},
		{"oversized", "", candidateBinaryLimit + 1, 1, io.EOF, nil, false, false},
		{"shrink", "binary\x00", 8, 1, io.EOF, nil, false, false},
		{"growth", "binary\x00!", 7, 1, io.EOF, nil, false, false},
		{"data_and_error", "binary\x00", 7, 32, readFailure, nil, true, false},
		{"probe_error", "binary\x00", 7, 1, readFailure, nil, false, false},
		{"close_error", "binary\x00", 7, 1, io.EOF, closeFailure, false, false},
		{"read_and_close_error", "binary\x00", 7, 1, readFailure, closeFailure, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := &candidateReadFixture{sourceReader{[]byte(tc.raw), tc.step, tc.readErr, tc.dataError}, tc.closeErr, false}
			digest, err := candidateDigest(input, tc.size)
			if !input.closed || (err == nil) != tc.ok || (!tc.ok && digest != "") {
				t.Fatal("candidate read returned an invalid digest or left its descriptor open")
			}
			if tc.ok {
				expected := sha256.Sum256([]byte(tc.raw))
				if digest != hex.EncodeToString(expected[:]) {
					t.Fatal("candidate read changed raw SHA-256 bytes")
				}
			}
			if tc.name == "read_and_close_error" && !errors.Is(err, readFailure) {
				t.Fatal("close failure replaced the actual read failure")
			}
		})
	}
	t.Log("offline-pilot-candidate-read-controls {\"schema_version\":1,\"controls\":12,\"complete_reads\":3,\"refusals\":9,\"inputs_closed\":true}")
}

func TestCandidateFileReadBounds(t *testing.T) {
	for _, mode := range []string{"missing", "empty", "oversized", "directory", "closed_descriptor", "opened_directory", "opened_empty", "opened_oversized", "opened_size_changed", "opened_replacement"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "PRIVATE_EXECUTABLE")
			if err := os.WriteFile(path, []byte("binary"), 0600); err != nil {
				t.Fatal("cannot prepare candidate file")
			}
			resize := func(size int64) {
				t.Helper()
				if os.Truncate(path, size) != nil {
					t.Fatal("cannot resize candidate file")
				}
			}
			remove := func() {
				t.Helper()
				if os.Remove(path) != nil {
					t.Fatal("cannot replace candidate file")
				}
			}
			switch mode {
			case "missing":
				remove()
			case "empty":
				resize(0)
			case "oversized":
				resize(candidateBinaryLimit + 1)
			case "directory":
				remove()
				if os.Mkdir(path, 0700) != nil {
					t.Fatal("cannot prepare candidate directory")
				}
			}
			called := false
			var opened *os.File
			file, size, err := checkedCandidateInput(path, func(name string) (*os.File, error) {
				called = true
				switch mode {
				case "opened_directory":
					remove()
					if os.Mkdir(path, 0700) != nil {
						t.Fatal("cannot prepare opened directory")
					}
				case "opened_empty":
					resize(0)
				case "opened_oversized":
					resize(candidateBinaryLimit + 1)
				case "opened_size_changed":
					resize(7)
				case "opened_replacement":
					// Keep the first inode live so it cannot be immediately reused.
					if os.Rename(path, path+".old") != nil || os.WriteFile(path, []byte("binary"), 0600) != nil {
						t.Fatal("cannot prepare regular replacement")
					}
				}
				var err error
				opened, err = openSourceInput(name)
				if err == nil && mode == "closed_descriptor" {
					err = opened.Close()
				}
				return opened, err
			})
			if err == nil || file != nil || size != 0 {
				if file != nil {
					_ = file.Close()
				}
				t.Fatal("candidate accepted an invalid path or descriptor")
			}
			preflight := mode == "missing" || mode == "empty" || mode == "oversized" || mode == "directory"
			if called == preflight {
				t.Fatal("candidate preflight reached open or descriptor validation was omitted")
			}
			if opened != nil {
				if _, err := opened.Stat(); err == nil {
					t.Fatal("refused candidate descriptor was left open")
				}
			}
			if preflight {
				if digest, size, err := candidateFileDigest(path); err == nil || digest != "" || size != 0 || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("invalid file returned a public digest or disclosed its path")
				}
			}
		})
	}
	path := filepath.Join(t.TempDir(), "bounded-binary")
	raw := []byte("binary\x00\xff")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("cannot prepare raw binary input")
	}
	expected := sha256.Sum256(raw)
	if digest, size, err := candidateFileDigest(path); err != nil || size != int64(len(raw)) || digest != hex.EncodeToString(expected[:]) {
		t.Fatal("regular binary digest changed")
	}
	if os.Truncate(path, 0) != nil || os.Truncate(path, candidateBinaryLimit) != nil {
		t.Fatal("cannot prepare exact candidate ceiling")
	}
	// Independently generated SHA-256 of 128 MiB of zero bytes, not the source
	// fingerprint helper (whose aggregate ceiling is only 64 MiB).
	const zeroSHA256 = "254bcc3fc4f27172636df4bf32de9f107f620d559b20d760197e452b97453917"
	if digest, size, err := candidateFileDigest(path); err != nil || size != candidateBinaryLimit || digest != zeroSHA256 {
		t.Fatal("exact 128 MiB candidate ceiling or raw digest was not preserved")
	}
	t.Log("offline-pilot-candidate-file-controls {\"schema_version\":1,\"controls\":12,\"accepted_files\":2,\"refusals\":10,\"binary_ceiling_bytes\":134217728,\"exact_ceiling_passed\":true,\"descriptors_closed\":true,\"replacement_identity_checked\":true}")
}
