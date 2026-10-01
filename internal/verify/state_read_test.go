package verify

import (
	"bytes"
	"errors"
	"io"
	"math"
	"reflect"
	"testing"
	"testing/iotest"
)

type stateReadFailure struct {
	input *bytes.Reader
	err   error
}

func (r stateReadFailure) Read(p []byte) (int, error) {
	n, err := r.input.Read(p)
	if r.input.Len() == 0 {
		return n, r.err // May return both bytes and a non-EOF error.
	}
	return n, err
}

func TestSizedStateReadContract(t *testing.T) {
	t.Run("byte_boundaries_and_stale_sizes", func(t *testing.T) {
		for _, limit := range []int{0, 1, 511, 512, 513, 4096} {
			for _, size := range []int{max(0, limit-1), limit, limit + 1, limit + 1024} {
				input := bytes.Repeat([]byte{0x81}, size)
				for _, hint := range []int64{-1, 0, 1, int64(limit / 2), int64(size), int64(limit + 1), math.MaxInt64} {
					for _, mode := range []string{"normal", "short", "data-and-eof"} {
						reader := bytes.NewReader(input)
						var source io.Reader = reader
						switch mode {
						case "short":
							source = iotest.OneByteReader(reader)
						case "data-and-eof":
							source = stateReadFailure{reader, io.EOF}
						}
						got, err := readStateBytes(source, int64(limit), hint)
						if size > limit {
							if !errors.Is(err, ErrStateFileTooLarge) || got != nil || reader.Len() != size-limit-1 {
								t.Fatalf("overflow escaped its one-byte probe: limit=%d size=%d hint=%d err=%v", limit, size, hint, err)
							}
						} else if err != nil || !bytes.Equal(got, input) || reader.Len() != 0 || cap(got) > limit+1 {
							t.Fatalf("hint changed bounded input: limit=%d size=%d hint=%d err=%v", limit, size, hint, err)
						}
					}
				}
			}
		}
	})
	t.Run("invalid_limits_before_reads", func(t *testing.T) {
		for _, limit := range []int64{-1, MaxStateFileBytes + 1, math.MaxInt64} {
			reader := bytes.NewReader([]byte("unread"))
			if got, err := readStateBytes(reader, limit, math.MaxInt64); !errors.Is(err, ErrInvalidRetainedState) || got != nil || reader.Len() != 6 {
				t.Fatal("invalid limit reached the input reader", err)
			}
		}
	})
	t.Run("read_errors_before_acceptance", func(t *testing.T) {
		failure := errors.New("synthetic state read failure")
		for _, size := range []int{0, 1, 3, 4, 513} {
			for _, hint := range []int64{0, 1, int64(size)} {
				reader := stateReadFailure{bytes.NewReader(make([]byte, size)), failure}
				// Include simultaneous read-error/overflow and full-buffer cases.
				if got, err := readStateBytes(reader, int64(max(0, size-1)), hint); !errors.Is(err, failure) || got != nil {
					t.Fatalf("read error was hidden: size=%d hint=%d err=%v", size, hint, err)
				}
			}
		}
	})
	t.Run("complete_saved_state_validation", func(t *testing.T) {
		_, raw := stateJSONFixture(t)
		want, err := decodeHeaderState(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		for _, hint := range []int64{1, int64(len(raw)), int64(len(raw) + 128)} {
			got, err := decodeSizedHeaderState(iotest.OneByteReader(bytes.NewReader(raw)), MaxStateFileBytes, hint)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("saved state changed with a stale size or short reads", err)
			}
			for _, bad := range [][]byte{
				append(bytes.Clone(raw), []byte(" null")...),
				raw[:len(raw)-1],
				append([]byte(`{"retained_window":[null],`), raw[1:]...),
			} {
				if got, err := decodeSizedHeaderState(bytes.NewReader(bad), MaxStateFileBytes, hint); err == nil || !got.Empty() {
					t.Fatal("allocation hint hid malformed, trailing or shadowed evidence")
				}
			}
			failure := errors.New("synthetic complete-JSON read failure")
			if got, err := decodeSizedHeaderState(stateReadFailure{bytes.NewReader(raw), failure}, MaxStateFileBytes, hint); !errors.Is(err, failure) || !got.Empty() {
				t.Fatal("complete JSON hid a read error", err)
			}
		}
	})
}

func FuzzSizedStateRead(f *testing.F) {
	for _, seed := range []struct {
		input string
		limit uint16
		hint  int64
	}{{"", 0, 0}, {"x", 0, 1}, {"abc", 3, 3}, {"abc", 2, 1}, {"{} trailing", 8, -1}, {"[]", 2, math.MaxInt64}} {
		f.Add([]byte(seed.input), seed.limit, seed.hint)
	}
	f.Fuzz(func(t *testing.T, input []byte, limit uint16, hint int64) {
		if len(input) > 8192 {
			t.Skip()
		}
		maxBytes := int64(limit % 4097)
		reader := bytes.NewReader(input)
		got, err := readStateBytes(reader, maxBytes, hint)
		// Compare with the previous bounded io.ReadAll contract, independently
		// of the new buffer's allocation and growth strategy.
		want, referenceErr := io.ReadAll(io.LimitReader(bytes.NewReader(input), maxBytes+1))
		if referenceErr != nil {
			t.Fatal(referenceErr)
		}
		if int64(len(want)) > maxBytes {
			if !errors.Is(err, ErrStateFileTooLarge) || got != nil || reader.Len() != len(input)-len(want) {
				t.Fatal("overflow differs from the bounded reference")
			}
		} else if err != nil || !bytes.Equal(got, want) || reader.Len() != 0 || int64(cap(got)) > maxBytes+1 {
			t.Fatal("accepted bytes differ from the bounded reference", err)
		}
	})
}
