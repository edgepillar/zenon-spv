package main

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"testing"
	"testing/iotest"
)

type inputTerminalReader struct {
	*bytes.Reader
	terminal error
	together bool
}

func (r inputTerminalReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if r.Len() == 0 && (n == 0 || r.together) {
		return n, r.terminal
	}
	return n, err
}

// Keep the previous byte/error contract independent of allocation hints.
func referenceInputRead(r io.Reader, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, os.ErrInvalid
	}
	return raw, nil
}

func checkInputRead(t testing.TB, input []byte, limit, hint int64, short, together bool, terminal error) {
	t.Helper()
	a, b := bytes.NewReader(input), bytes.NewReader(input)
	var actual io.Reader = inputTerminalReader{a, terminal, together}
	var reference io.Reader = inputTerminalReader{b, terminal, together}
	if short {
		actual, reference = iotest.OneByteReader(actual), iotest.OneByteReader(reference)
	}
	got, err := readInputBytes(actual, limit, hint)
	want, expectedErr := referenceInputRead(reference, limit)
	if !bytes.Equal(got, want) || (err == nil) != (expectedErr == nil) ||
		errors.Is(err, os.ErrInvalid) != errors.Is(expectedErr, os.ErrInvalid) || a.Len() != b.Len() {
		t.Fatalf("hint changed bounded read: size=%d limit=%d hint=%d", len(input), limit, hint)
	}
	if err != nil && got != nil || err == nil && int64(cap(got)) > limit+1 {
		t.Fatal("partial bytes or buffer capacity escaped the input boundary")
	}
}

func TestConsumerInputReadContract(t *testing.T) {
	t.Run("byte_boundaries_and_stale_sizes", func(t *testing.T) {
		for _, limit := range []int64{0, 1, 511, 512, 513, 4096} {
			for _, size := range []int64{max(0, limit-1), limit, limit + 1, limit + 1024} {
				for _, hint := range []int64{math.MinInt64, -1, 0, 1, limit / 2, size, limit + 1, math.MaxInt64} {
					for _, short := range []bool{false, true} {
						for _, together := range []bool{false, true} {
							checkInputRead(t, bytes.Repeat([]byte{0x81}, int(size)), limit, hint, short, together, io.EOF)
						}
					}
				}
			}
		}
	})
	t.Run("read_errors_discard_complete_or_overflow_bytes", func(t *testing.T) {
		for _, input := range [][]byte{nil, []byte("{}"), bytes.Repeat([]byte{0x81}, 513)} {
			for _, limit := range []int64{0, int64(max(0, len(input)-1)), int64(len(input)), int64(len(input) + 1)} {
				for _, hint := range []int64{0, 1, int64(len(input)), math.MaxInt64} {
					for _, together := range []bool{false, true} {
						checkInputRead(t, input, limit, hint, false, together, io.ErrUnexpectedEOF)
					}
				}
			}
		}
	})
	t.Run("invalid_limits_before_reads", func(t *testing.T) {
		for _, limit := range []int64{-1, maxReportBytes + 1, math.MaxInt64} {
			input := bytes.NewReader([]byte("unread"))
			if raw, err := readInputBytes(input, limit, math.MaxInt64); raw != nil || !errors.Is(err, os.ErrInvalid) || input.Len() != 6 {
				t.Fatal("invalid limit reached the reader")
			}
		}
	})
	t.Run("consumer_caps_and_complete_document_bytes", func(t *testing.T) {
		for _, limit := range []int64{maxExpectationsBytes, maxReportBytes} {
			for _, size := range []int64{limit - 1, limit, limit + 1} {
				for _, hint := range []int64{1, size, math.MaxInt64} {
					checkInputRead(t, bytes.Repeat([]byte{' '}, int(size)), limit, hint, false, false, io.EOF)
				}
			}
		}
		for _, input := range [][]byte{[]byte(`{"schema_version":1}`), []byte(`{"schema_version":1} null`), []byte(`{"schema_version":`)} {
			for _, hint := range []int64{1, int64(len(input)), int64(len(input) + 128)} {
				checkInputRead(t, input, maxExpectationsBytes, hint, true, true, io.EOF)
			}
		}
	})
}

func FuzzConsumerInputRead(f *testing.F) {
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
		checkInputRead(t, input, int64(limit%4097), hint, mode&1 != 0, mode&2 != 0, terminal)
	})
}
