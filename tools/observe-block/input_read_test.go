package main

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"
	"testing/iotest"
)

// Preserve the ordinary reader selected from fork main 367281d. This byte/error
// baseline does not use the candidate allocation hint or growth implementation.
func previousExpectationBytes(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit+1))
}

type expectationTerminalReader struct {
	*bytes.Reader
	terminal error
	together bool
}

func (r expectationTerminalReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if r.Len() == 0 && (n == 0 || r.together) {
		return n, r.terminal
	}
	return n, err
}

func compareExpectationRead(t testing.TB, input []byte, limit, hint int64, short, together bool, terminal error) {
	t.Helper()
	a, b := bytes.NewReader(input), bytes.NewReader(input)
	var actual io.Reader = expectationTerminalReader{a, terminal, together}
	var reference io.Reader = expectationTerminalReader{b, terminal, together}
	if short {
		actual, reference = iotest.OneByteReader(actual), iotest.OneByteReader(reference)
	}
	got, err := readExpectationBytes(actual, limit, hint)
	want, previousErr := previousExpectationBytes(reference, limit)
	if !bytes.Equal(got, want) || !errors.Is(err, previousErr) || (err == nil) != (previousErr == nil) || a.Len() != b.Len() {
		t.Fatal("allocation hint changed complete raw bytes, failure or consumed input")
	}
	if int64(cap(got)) > limit+1 || int64(len(got)) > limit+1 {
		t.Fatal("snapshot buffer exceeded its overflow-byte boundary")
	}
}

func TestObserverExpectationsReadContract(t *testing.T) {
	t.Run("byte_boundaries_and_stale_sizes", func(t *testing.T) {
		for _, limit := range []int64{0, 1, 511, 512, 513, 4096} {
			for _, size := range []int64{max(0, limit-1), limit, limit + 1, limit + 1024} {
				for _, hint := range []int64{math.MinInt64, -1, 0, 1, limit / 2, size, limit + 1, math.MaxInt64} {
					for _, short := range []bool{false, true} {
						for _, together := range []bool{false, true} {
							compareExpectationRead(t, bytes.Repeat([]byte{0x81}, int(size)), limit, hint, short, together, io.EOF)
						}
					}
				}
			}
		}
	})
	t.Run("read_failures_preserve_raw_bytes_and_refusal", func(t *testing.T) {
		for _, input := range [][]byte{nil, []byte("{}"), bytes.Repeat([]byte{0x81}, 513)} {
			for _, limit := range []int64{0, int64(max(0, len(input)-1)), int64(len(input)), int64(len(input) + 1)} {
				for _, hint := range []int64{0, 1, int64(len(input)), math.MaxInt64} {
					for _, together := range []bool{false, true} {
						compareExpectationRead(t, input, limit, hint, false, together, io.ErrUnexpectedEOF)
					}
				}
			}
		}
	})
	t.Run("raw_documents_and_maximum_byte_boundary", func(t *testing.T) {
		for _, size := range []int{maxExpectationsBytes - 1, maxExpectationsBytes, maxExpectationsBytes + 1, maxExpectationsBytes + 1024} {
			for _, hint := range []int64{1, int64(size), math.MaxInt64} {
				compareExpectationRead(t, bytes.Repeat([]byte{' '}, size), maxExpectationsBytes, hint, false, false, io.EOF)
			}
		}
		for _, input := range [][]byte{[]byte(`{"schema_version":1}`), []byte(`{"schema_version":1} null`), []byte(`{"schema_version":`)} {
			for _, hint := range []int64{1, int64(len(input)), int64(len(input) + 128)} {
				compareExpectationRead(t, input, maxExpectationsBytes, hint, true, true, io.EOF)
			}
		}
	})
	t.Run("invalid_limits_before_reads", func(t *testing.T) {
		for _, limit := range []int64{-1, maxExpectationsBytes + 1, math.MaxInt64} {
			input := bytes.NewReader([]byte("unread"))
			if raw, err := readExpectationBytes(input, limit, math.MaxInt64); raw != nil || !errors.Is(err, os.ErrInvalid) || input.Len() != 6 {
				t.Fatal("invalid limit reached the reader")
			}
		}
	})
	t.Run("opened_descriptor_size", func(t *testing.T) {
		for _, sizes := range [][2]int{{1, 699}, {699, 1}} {
			path := filepath.Join(t.TempDir(), "PRIVATE_INPUT")
			if os.WriteFile(path, bytes.Repeat([]byte{0x82}, sizes[0]), 0o600) != nil {
				t.Fatal("cannot prepare selected input")
			}
			opened := bytes.Repeat([]byte{0x81}, sizes[1])
			f, size, err := checkedPreflightInput(path, maxExpectationsBytes, func(name string) (*os.File, error) {
				if os.Remove(name) != nil || os.WriteFile(name, opened, 0o600) != nil {
					t.Fatal("cannot prepare replacement input")
				}
				return openPreflightInput(name)
			})
			if err != nil {
				t.Fatal("cannot open replacement input")
			}
			raw, readErr := readExpectationBytes(f, maxExpectationsBytes, size)
			closeErr := f.Close()
			if size != int64(len(opened)) || !bytes.Equal(raw, opened) || readErr != nil || closeErr != nil {
				t.Fatal("snapshot used selected pathname metadata instead of opened descriptor bytes")
			}
		}
	})
}

func FuzzObserverExpectationsRead(f *testing.F) {
	for _, seed := range []struct {
		input string
		limit uint16
		hint  int64
		mode  uint8
	}{{"", 0, 0, 0}, {"abc", 3, 3, 0}, {"abc", 2, 1, 0}, {"{} null", 8, -1, 3}, {"{}", 2, math.MaxInt64, 4}} {
		f.Add([]byte(seed.input), seed.limit, seed.hint, seed.mode)
	}
	f.Fuzz(func(t *testing.T, input []byte, limit uint16, hint int64, mode uint8) {
		if len(input) > 8192 {
			return
		}
		terminal := io.EOF
		if mode&4 != 0 {
			terminal = io.ErrUnexpectedEOF
		}
		compareExpectationRead(t, input, int64(limit%4097), hint, mode&1 != 0, mode&2 != 0, terminal)
	})
}
