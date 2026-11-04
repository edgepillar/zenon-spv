package conformance_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

const cliStateCompareBufferBytes = 32 << 10

// Retain the original byte-for-byte oracle, including the separately retained
// expected bytes. Repeated checks need only a bounded read buffer. No digest,
// size-only shortcut, shared scratch buffer or cached comparison replaces EOF.
func equalCLIStateFile(path string, expected []byte) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	equal := equalCLIStateReader(f, expected)
	return f.Close() == nil && equal
}

func equalCLIStateReader(r io.Reader, expected []byte) bool {
	size := cliStateCompareBufferBytes
	if len(expected) < size {
		size = len(expected) + 1
	}
	buffer := make([]byte, size)
	offset, emptyReads := 0, 0
	for {
		remaining := len(expected) - offset
		limit := len(buffer)
		if remaining < limit {
			limit = remaining + 1 // At most one extra byte can disprove equality.
		}
		n, err := r.Read(buffer[:limit])
		if n < 0 || n > limit || n > remaining || !bytes.Equal(buffer[:n], expected[offset:offset+n]) {
			return false
		}
		offset += n
		if err != nil {
			return err == io.EOF && offset == len(expected)
		}
		if n == 0 {
			emptyReads++
			if emptyReads == 100 {
				return false
			}
		} else {
			emptyReads = 0
		}
	}
}

type cliStateShortReader struct {
	reader   *bytes.Reader
	chunk    int
	consumed int
	maxRead  int
}

func (r *cliStateShortReader) Read(p []byte) (int, error) {
	r.maxRead = max(r.maxRead, len(p))
	p = p[:min(len(p), r.chunk)]
	n, err := r.reader.Read(p)
	r.consumed += n
	return n, err
}

func TestCLIStateReaderComparison(t *testing.T) {
	for _, size := range []int{0, 1, cliStateCompareBufferBytes - 1, cliStateCompareBufferBytes, cliStateCompareBufferBytes + 1, 2*cliStateCompareBufferBytes + 17} {
		expected := make([]byte, size)
		for i := range expected {
			expected[i] = byte(i*31 + i/257)
		}
		original := bytes.Clone(expected)
		for _, chunk := range []int{1, 7, cliStateCompareBufferBytes + 1} {
			for _, kind := range []string{"same", "shorter", "longer", "first", "middle", "last"} {
				actual := bytes.Clone(expected)
				switch kind {
				case "shorter":
					if size == 0 {
						continue
					}
					actual = actual[:size-1]
				case "longer":
					actual = append(actual, 0)
				case "first", "middle", "last":
					if size == 0 {
						continue
					}
					index := map[string]int{"first": 0, "middle": size / 2, "last": size - 1}[kind]
					actual[index] ^= 1
				}
				r := &cliStateShortReader{reader: bytes.NewReader(actual), chunk: chunk}
				if equalCLIStateReader(r, expected) != bytes.Equal(actual, expected) {
					t.Fatalf("byte comparison differed for size=%d chunk=%d case=%s", size, chunk, kind)
				}
				if r.maxRead > cliStateCompareBufferBytes || r.consumed > size+1 || !bytes.Equal(original, expected) {
					t.Fatal("comparison exceeded its buffer/read bound or modified the oracle")
				}
			}
		}
	}
}

type cliStateTerminalReader struct {
	data []byte
	err  error
}

func (r cliStateTerminalReader) Read(p []byte) (int, error) {
	return copy(p, r.data), r.err
}

type cliStateEmptyReader struct{ calls int }

func (r *cliStateEmptyReader) Read([]byte) (int, error) {
	r.calls++
	return 0, nil
}

func TestCLIStateReaderCompletion(t *testing.T) {
	want := []byte("selected bytes")
	for _, tc := range []struct {
		name string
		r    io.Reader
		want bool
	}{
		{"data-and-eof", cliStateTerminalReader{want, io.EOF}, true},
		{"data-and-error", cliStateTerminalReader{want, errors.New("read failed")}, false},
		{"short-data-and-eof", cliStateTerminalReader{want[:3], io.EOF}, false},
		{"no-data-and-error", cliStateTerminalReader{nil, errors.New("read failed")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if equalCLIStateReader(tc.r, want) != tc.want {
				t.Fatal("comparison lost read completion or error")
			}
		})
	}
	stalled := &cliStateEmptyReader{}
	if equalCLIStateReader(stalled, want) || stalled.calls != 100 {
		t.Fatal("zero-progress reads were accepted or left unbounded")
	}
}

func TestCLIStateFileComparison(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	want := bytes.Repeat([]byte{0x5a}, 3*cliStateCompareBufferBytes+17)
	for _, actual := range [][]byte{want, want[:len(want)-1], append(bytes.Clone(want), 0), nil} {
		if err := os.WriteFile(path, actual, 0o600); err != nil {
			t.Fatal(err)
		}
		if equalCLIStateFile(path, want) != bytes.Equal(actual, want) {
			t.Fatal("regular-file comparison differed from complete byte equality")
		}
	}
	if equalCLIStateFile(filepath.Join(t.TempDir(), "missing.json"), nil) {
		t.Fatal("an unavailable file became an equal empty file")
	}
}

// The paired reference models the previous os.ReadFile + bytes.Equal check.
// Fixtures, expected bytes and filesystem setup are outside each timer. This
// measures only the comparison, not observer/child latency or peak memory.
func BenchmarkCLIStateFileComparison(b *testing.B) {
	for _, tc := range []struct {
		name string
		size int
	}{{"2KiB", 2 << 10}, {"1MiB", 1 << 20}, {"8MiB", 8 << 20}} {
		for _, implementation := range []string{"whole-file", "bounded"} {
			b.Run(tc.name+"/"+implementation, func(b *testing.B) {
				want := bytes.Repeat([]byte{0x5a}, tc.size)
				path := filepath.Join(b.TempDir(), "state.json")
				if err := os.WriteFile(path, want, 0o600); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.SetBytes(int64(tc.size))
				b.ResetTimer()
				for range b.N {
					if implementation == "whole-file" {
						actual, err := os.ReadFile(path)
						if err != nil || !bytes.Equal(actual, want) {
							b.Fatal("reference comparison failed")
						}
					} else if !equalCLIStateFile(path, want) {
						b.Fatal("bounded comparison failed")
					}
				}
			})
		}
	}
}
