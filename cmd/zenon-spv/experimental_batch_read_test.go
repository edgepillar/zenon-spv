// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"
)

// Only in-memory inputs: no file, link, service or build fixture is created.
type experimentalCLIReadSource struct {
	input    *bytes.Reader
	chunk    int
	terminal error
	zeros    int
}

func (r *experimentalCLIReadSource) Read(p []byte) (int, error) {
	if r.zeros > 0 {
		r.zeros--
		return 0, nil
	}
	if r.chunk > 0 && len(p) > r.chunk {
		p = p[:r.chunk]
	}
	n, err := r.input.Read(p)
	if r.input.Len() == 0 && r.terminal != nil {
		return n, r.terminal
	}
	return n, err
}

func TestExperimentalCLIReadBoundaries(t *testing.T) {
	for _, limit := range []int{1, 31, 511, 512, 513, 4096} {
		for _, size := range []int{0, limit - 1, limit, limit + 1, limit + 17} {
			input := bytes.Repeat([]byte{0x81}, size)
			for _, hint := range []int64{-1, 0, 1, int64(limit / 2), int64(size), int64(limit + 1), math.MaxInt64} {
				for _, chunk := range []int{0, 7} {
					for _, terminal := range []error{nil, io.EOF} {
						actual := &experimentalCLIReadSource{input: bytes.NewReader(input), chunk: chunk, terminal: terminal, zeros: 2}
						reference := &experimentalCLIReadSource{input: bytes.NewReader(input), chunk: chunk, terminal: terminal, zeros: 2}
						// Keep the previous bounded ReadAll behavior as the byte oracle.
						want, wantErr := io.ReadAll(io.LimitReader(reference, int64(limit)+1))
						if wantErr != nil {
							t.Fatal(wantErr)
						}
						got, err := readExperimentalCLIBytes(actual, int64(limit), hint)
						if actual.input.Len() != reference.input.Len() {
							t.Fatal("size hint changed consumption or the single overflow probe")
						}
						if len(want) > limit {
							if !errors.Is(err, errExperimentalCLIInput) || got != nil {
								t.Fatal("overflow returned input bytes", err)
							}
						} else if err != nil || !bytes.Equal(got, want) || cap(got) > limit+1 {
							t.Fatalf("bounded reference mismatch: limit=%d size=%d hint=%d chunk=%d err=%v", limit, size, hint, chunk, err)
						}
					}
				}
			}
		}
	}
}

func TestExperimentalCLIReadRefusals(t *testing.T) {
	t.Run("invalid_limit_before_read", func(t *testing.T) {
		for _, limit := range []int64{-1, 0, maxExperimentalBundleBytes + 1, math.MaxInt64} {
			input := bytes.NewReader([]byte("unread"))
			if got, err := readExperimentalCLIBytes(input, limit, 1); !errors.Is(err, errExperimentalCLIInput) || got != nil || input.Len() != 6 {
				t.Fatal("invalid limit reached the input", err)
			}
		}
	})
	t.Run("read_error_returns_no_bytes", func(t *testing.T) {
		failure := errors.New("synthetic read failure")
		for _, size := range []int{0, 1, 3, 4, 513} {
			for _, hint := range []int64{0, 1, int64(size)} {
				for _, chunk := range []int{0, 7} {
					for _, limit := range []int64{int64(max(1, size-1)), int64(max(1, size)), int64(size + 1)} {
						input := &experimentalCLIReadSource{input: bytes.NewReader(make([]byte, size)), chunk: chunk, terminal: failure}
						if got, err := readExperimentalCLIBytes(input, limit, hint); !errors.Is(err, errExperimentalCLIInput) || got != nil {
							t.Fatal("complete, partial or overflowing input hid a read error", err)
						}
					}
				}
			}
		}
	})
}

func TestExperimentalCLIReadStableFileCapacity(t *testing.T) {
	for _, size := range []int{maxExperimentalRequestBytes, maxExperimentalConfigBytes, maxExperimentalBundleBytes} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			input := bytes.Repeat([]byte{0x82}, size)
			got, err := readExperimentalCLIBytes(bytes.NewReader(input), int64(size), int64(size))
			if err != nil || !bytes.Equal(got, input) || cap(got) != size+1 {
				t.Fatal("stable input did not retain its bounded allocation hint", err)
			}
			got[0] ^= 1
			if input[0] != 0x82 {
				t.Fatal("returned input aliases the reader's backing bytes")
			}
		})
	}
}

func FuzzExperimentalCLIRead(f *testing.F) {
	for _, seed := range []string{"", "x", "{}", "[] trailing"} {
		f.Add([]byte(seed), uint16(len(seed)+1), int64(len(seed)), uint8(0), false)
	}
	f.Fuzz(func(t *testing.T, input []byte, limit uint16, hint int64, chunk uint8, fail bool) {
		if len(input) > 8192 {
			t.Skip()
		}
		maxBytes := int64(limit%4096) + 1
		terminal := io.EOF
		if fail {
			terminal = io.ErrUnexpectedEOF
		}
		actual := &experimentalCLIReadSource{input: bytes.NewReader(input), chunk: int(chunk % 8), terminal: terminal}
		reference := &experimentalCLIReadSource{input: bytes.NewReader(input), chunk: int(chunk % 8), terminal: terminal}
		want, wantErr := io.ReadAll(io.LimitReader(reference, maxBytes+1))
		got, err := readExperimentalCLIBytes(actual, maxBytes, hint)
		if actual.input.Len() != reference.input.Len() {
			t.Fatal("bounded read consumption changed")
		}
		if wantErr != nil || int64(len(want)) > maxBytes {
			if !errors.Is(err, errExperimentalCLIInput) || got != nil {
				t.Fatal("failed reference returned bytes", err)
			}
		} else if err != nil || !bytes.Equal(got, want) || int64(cap(got)) > maxBytes+1 {
			t.Fatal("bounded read reference changed", err)
		}
	})
}

func BenchmarkExperimentalCLIRead(b *testing.B) {
	for _, size := range []int{maxExperimentalRequestBytes, maxExperimentalConfigBytes, maxExperimentalBundleBytes} {
		input := bytes.Repeat([]byte{0x81}, size)
		for _, mode := range []string{"bounded_read_all_reference", "opened_size_hint"} {
			b.Run(fmt.Sprint(size, "/", mode), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for i := 0; i < b.N; i++ {
					var got []byte
					var err error
					if mode == "opened_size_hint" {
						got, err = readExperimentalCLIBytes(bytes.NewReader(input), int64(size), int64(size))
					} else {
						got, err = io.ReadAll(io.LimitReader(bytes.NewReader(input), int64(size)+1))
					}
					if err != nil || !bytes.Equal(got, input) {
						b.Fatal("unexpected input bytes", err)
					}
				}
			})
		}
	}
}
