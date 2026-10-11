package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sourceReader struct {
	raw       []byte
	chunk     int
	err       error
	dataError bool
}

func (r *sourceReader) Read(out []byte) (int, error) {
	n := min(len(out), len(r.raw), r.chunk)
	copy(out, r.raw[:n])
	r.raw = r.raw[n:]
	if n == 0 || (len(r.raw) == 0 && r.dataError) {
		return n, r.err
	}
	return n, nil
}

func TestSourceReadContract(t *testing.T) {
	readFailure := errors.New("PRIVATE_SOURCE_READ_FAILURE")
	tests := []struct {
		name string
		raw  string
		size int64
		step int
		err  error
		ok   bool
	}{
		{"empty", "", 0, 1, io.EOF, true},
		{"complete", "source bytes", 12, 32, io.EOF, true},
		{"short reads", "source bytes", 12, 1, io.EOF, true},
		{"shrink", "source bytes", 13, 1, io.EOF, false},
		{"growth", "source bytes!", 12, 1, io.EOF, false},
		{"data and error", "source bytes", 12, 32, readFailure, false},
		{"probe error", "source bytes", 12, 1, readFailure, false},
		{"empty error", "", 0, 1, readFailure, false},
		{"negative size", "", -1, 1, io.EOF, false},
		{"oversized", "", maxSourceBytes + 1, 1, io.EOF, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			reader := &sourceReader{raw: []byte(tc.raw), chunk: tc.step, err: tc.err, dataError: tc.name == "data and error"}
			err := copySourceBytes(&out, reader, tc.size, make([]byte, 3))
			if (err == nil) != tc.ok || (tc.ok && out.String() != tc.raw) {
				t.Fatal("incomplete or failed source read changed the fingerprint contract")
			}
		})
	}
	for _, short := range []bool{false, true} {
		if copySourceBytes(failingWriter{short}, strings.NewReader("abc"), 3, make([]byte, 2)) == nil {
			t.Fatal("hash sink failure was accepted")
		}
	}
	if copySourceBytes(io.Discard, strings.NewReader(""), 0, nil) == nil {
		t.Fatal("missing copy buffer was accepted")
	}
	t.Log("offline-pilot-source-read-controls {\"schema_version\":1,\"controls\":13,\"complete_reads\":3,\"refusals\":10}")
}

func TestSourceFingerprintStreamAndBounds(t *testing.T) {
	t.Chdir(t.TempDir())
	paths := []string{"alpha.go", "empty.json", "fixture.json"}
	values := [][]byte{bytes.Repeat([]byte("source bytes\n"), 8192), {}, []byte("{\"fixture\":true}\n")}
	var historical bytes.Buffer
	for i, name := range paths {
		if os.WriteFile(name, values[i], 0600) != nil {
			t.Fatal("cannot prepare selected source input")
		}
		// Independent full-buffer encoding of the prior length-prefixed format.
		if binary.Write(&historical, binary.BigEndian, uint64(len(name))) != nil ||
			binary.Write(&historical, binary.BigEndian, []byte(name)) != nil ||
			binary.Write(&historical, binary.BigEndian, uint64(len(values[i]))) != nil ||
			binary.Write(&historical, binary.BigEndian, values[i]) != nil {
			t.Fatal("cannot encode historical source input")
		}
	}
	selected := sha256.Sum256(historical.Bytes())
	actual, err := hashSourceInputs(paths, openSourceInput)
	if err != nil || actual != hex.EncodeToString(selected[:]) {
		t.Fatal("streamed fingerprint changed prior bytes")
	}
	var opened []*os.File
	open := func(path string) (*os.File, error) {
		f, err := openSourceInput(path)
		if err == nil {
			opened = append(opened, f)
		}
		return f, err
	}
	assertClosed := func() {
		t.Helper()
		for _, f := range opened {
			if _, err := f.Stat(); err == nil {
				t.Fatal("source descriptor was left open")
			}
		}
		opened = nil
	}
	resize := func(size int64) {
		t.Helper()
		if os.Truncate(paths[0], size) != nil {
			t.Fatal("cannot resize selected regular source input")
		}
	}
	// Exact aggregate ceiling includes every member, including empty files.
	resize(maxSourceBytes - int64(len(values[2])))
	if pin, err := hashSourceInputs(paths, open); err != nil || !hexDigest(pin, 64) {
		t.Fatal("exact aggregate ceiling was refused")
	}
	assertClosed()
	resize(maxSourceBytes - int64(len(values[2])) + 1)
	if pin, err := hashSourceInputs(paths, open); err == nil || pin != "" || len(opened) != 2 {
		t.Fatal("aggregate overflow opened the member or returned a partial fingerprint")
	}
	assertClosed()
	resize(maxSourceBytes + 1)
	if pin, err := hashSourceInputs(paths[:1], open); err == nil || pin != "" || len(opened) != 0 {
		t.Fatal("oversized member was read")
	}
	resize(3)
	for _, size := range []int64{2, 4} {
		changed := func(path string) (*os.File, error) {
			f, _, err := checkedSourceInput(path, maxSourceBytes, openSourceInput)
			if err == nil {
				if os.Truncate(path, size) != nil {
					_ = f.Close()
					t.Fatal("cannot change opened source size")
				}
			}
			return f, err
		}
		// Exercise the real descriptor's stale size using the copy primitive.
		f, err := changed(paths[0])
		if err != nil || copySourceBytes(io.Discard, f, 3, make([]byte, 2)) == nil {
			if f != nil {
				_ = f.Close()
			}
			t.Fatal("changed opened source size was accepted")
		}
		_ = f.Close()
		resize(3)
	}
	t.Log("offline-pilot-source-fingerprint-controls {\"schema_version\":1,\"historical_encoding_matched\":true,\"aggregate_ceiling_bytes\":67108864,\"exact_ceiling_passed\":true,\"refusals\":4,\"descriptors_closed\":true}")
}

func TestSourceInputPreflight(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "member.go")
	if os.WriteFile(path, []byte("abc"), 0600) != nil {
		t.Fatal("cannot prepare input")
	}
	for _, remaining := range []int64{-1, 0, 2} {
		called := false
		f, _, err := checkedSourceInput(path, remaining, func(string) (*os.File, error) { called = true; return nil, os.ErrInvalid })
		if err == nil || f != nil || called {
			t.Fatal("invalid remaining ceiling reached open")
		}
	}
	var opened *os.File
	f, _, err := checkedSourceInput(path, 3, func(name string) (*os.File, error) {
		if os.Truncate(name, 4) != nil {
			return nil, os.ErrInvalid
		}
		var err error
		opened, err = openSourceInput(name)
		return opened, err
	})
	if err == nil || f != nil || opened == nil {
		t.Fatal("oversized replacement descriptor was accepted")
	}
	if _, err := opened.Stat(); err == nil {
		t.Fatal("rejected descriptor was left open")
	}
	if f, _, err := checkedSourceInput(dir, 4, openSourceInput); err == nil || f != nil {
		t.Fatal("source directory was accepted")
	}
	t.Log("offline-pilot-source-preflight-controls {\"schema_version\":1,\"refusals\":5,\"descriptors_closed\":true}")
}

func BenchmarkSourceInputHash(b *testing.B) {
	for _, size := range []int{128 << 10, 1 << 20, 8 << 20} {
		b.Run(map[int]string{128 << 10: "128KiB", 1 << 20: "1MiB", 8 << 20: "8MiB"}[size], func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "selected.json")
			if os.WriteFile(path, bytes.Repeat([]byte{'x'}, size), 0600) != nil {
				b.Fatal("cannot prepare source member")
			}
			for _, mode := range []string{"prior_buffered", "streamed"} {
				b.Run(mode, func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(size))
					for b.Loop() {
						if mode == "streamed" {
							if _, err := hashSourceInputs([]string{path}, openSourceInput); err != nil {
								b.Fatal("streamed source member failed")
							}
						} else {
							// Preserve the old full-file reader and complete hash encoding.
							raw, err := os.ReadFile(path)
							if err != nil {
								b.Fatal("historical source member failed")
							}
							h := sha256.New()
							_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(path))))
							_, _ = io.WriteString(h, path)
							_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(raw))))
							_, _ = h.Write(raw)
							_ = hex.EncodeToString(h.Sum(nil))
						}
					}
				})
			}
		})
	}
}
