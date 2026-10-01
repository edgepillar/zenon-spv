package proof

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

type bundleTerminalReader struct {
	input    *bytes.Reader
	terminal error
	together bool
}

func (r bundleTerminalReader) Read(p []byte) (int, error) {
	n, err := r.input.Read(p)
	if r.input.Len() == 0 && (n == 0 || r.together) {
		return n, r.terminal
	}
	return n, err
}

// Keep the former LimitReader + ReadAll contract as an independent reference,
// including its saturated probe and read-error priority. Do not use the new
// allocation helper or a size hint here.
func referenceBundleRead(r io.Reader, limit int64) ([]byte, error) {
	if limit > 0 {
		probe := limit
		if probe != math.MaxInt64 {
			probe++
		}
		r = io.LimitReader(r, probe)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	if limit > 0 && int64(len(raw)) > limit {
		return nil, fmt.Errorf("%w: max=%d bytes, file is at least %d bytes", ErrBundleTooLarge, limit, len(raw))
	}
	return raw, nil
}

func checkBundleReadReference(t testing.TB, input []byte, limit, hint int64, short, together bool, terminal error) {
	t.Helper()
	actual, reference := bytes.NewReader(input), bytes.NewReader(input)
	var a io.Reader = bundleTerminalReader{actual, terminal, together}
	var b io.Reader = bundleTerminalReader{reference, terminal, together}
	if short {
		a, b = iotest.OneByteReader(a), iotest.OneByteReader(b)
	}
	got, err := readBundleBytes(a, limit, hint)
	want, expectedErr := referenceBundleRead(b, limit)
	if !bytes.Equal(got, want) || actual.Len() != reference.Len() || fmt.Sprint(err) != fmt.Sprint(expectedErr) {
		t.Fatalf("bounded read changed: limit=%d hint=%d size=%d got=%v want=%v", limit, hint, len(input), err, expectedErr)
	}
	if err != nil && got != nil {
		t.Fatal("read failure exposed partial bytes")
	}
	for _, cause := range []error{ErrBundleTooLarge, terminal} {
		if errors.Is(err, cause) != errors.Is(expectedErr, cause) {
			t.Fatal("read error lost its original cause")
		}
	}
}

type bundleReadRequest struct {
	*bytes.Reader
	largest int
}

func (r *bundleReadRequest) Read(p []byte) (int, error) {
	r.largest = max(r.largest, len(p))
	return r.Reader.Read(p)
}

func TestSizedBundleReadContract(t *testing.T) {
	t.Run("byte_boundaries_and_stale_sizes", func(t *testing.T) {
		for _, size := range []int{0, 1, 2, 511, 512, 513, 2048} {
			input := bytes.Repeat([]byte{0x81}, size)
			for _, limit := range []int64{-1, 0, 1, int64(size), int64(size + 1), 512, math.MaxInt64} {
				for _, hint := range []int64{-1, 0, 1, int64(size - 1), int64(size), int64(size + 11), math.MaxInt64} {
					for _, short := range []bool{false, true} {
						for _, together := range []bool{false, true} {
							checkBundleReadReference(t, input, limit, hint, short, together, io.EOF)
						}
					}
				}
			}
		}
	})
	t.Run("read_error_priority", func(t *testing.T) {
		failure := errors.New("synthetic bundle read failure")
		for _, size := range []int{0, 1, 3, 4, 513} {
			for _, limit := range []int64{0, int64(max(1, size-1)), int64(size), math.MaxInt64} {
				for _, hint := range []int64{0, 1, int64(size), int64(size + 1)} {
					for _, terminal := range []error{failure, io.ErrUnexpectedEOF} {
						for _, together := range []bool{false, true} {
							checkBundleReadReference(t, make([]byte, size), limit, hint, false, together, terminal)
						}
					}
				}
			}
		}
	})
	t.Run("unusable_hints_do_not_allocate_the_reported_size", func(t *testing.T) {
		for _, limit := range []int64{-1, 0, 8, math.MaxInt64} {
			for _, hint := range []int64{math.MinInt64, -1, 0, maxBundleReadHintBytes + 1, math.MaxInt64} {
				reader := &bundleReadRequest{Reader: bytes.NewReader([]byte("input"))}
				if raw, err := readBundleBytes(reader, limit, hint); err != nil || string(raw) != "input" || reader.largest > 1024 {
					t.Fatal("unusable metadata triggered an eager allocation or changed input", err)
				}
			}
		}
	})
	t.Run("complete_document_validation", func(t *testing.T) {
		valid := []byte(`{"version":1,"headers":[]}`)
		want, err := unmarshalHeaderBundleJSON(valid, DecodeLimits{MaxHeaders: 1})
		if err != nil {
			t.Fatal(err)
		}
		for _, hint := range []int64{1, int64(len(valid)), int64(len(valid) + 128)} {
			raw, err := readBundleBytes(iotest.OneByteReader(bytes.NewReader(valid)), 65536, hint)
			if err != nil {
				t.Fatal(err)
			}
			got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxHeaders: 1})
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("hint changed the complete bundle", err)
			}
			for _, bad := range [][]byte{
				append(bytes.Clone(valid), []byte(" null")...), valid[:len(valid)-1],
				[]byte(`{"version":1,"headers":[{}],"HEADERS":[]}`),
				[]byte(`{"version":1,"headers":[{},"PRIVATE_UNREACHED_ROW"]}`),
				[]byte(`{"version":1,"extension":` + strings.Repeat("[", 10000) + "0" + strings.Repeat("]", 10000) + "}"),
			} {
				raw, err := readBundleBytes(bytes.NewReader(bad), 65536, hint)
				if err != nil {
					t.Fatal(err)
				}
				got, err := unmarshalHeaderBundleJSON(raw, DecodeLimits{MaxHeaders: 1})
				if err == nil || !reflect.DeepEqual(got, HeaderBundle{}) || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("hint hid malformed, shadowed or excess evidence", err)
				}
			}
		}
	})
	t.Run("regular_file_loader_preserves_limits", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bundle.json")
		raw := []byte(`{"version":1,"headers":[{},{}]}`)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, limit := range []int64{-1, 0, int64(len(raw)), math.MaxInt64} {
			got, err := LoadHeaderBundleWithLimits(path, limit, DecodeLimits{MaxHeaders: 2})
			if err != nil || len(got.Headers) != 2 {
				t.Fatal("regular-file hint changed accepted input", err)
			}
		}
		if _, err := LoadHeaderBundleWithLimits(path, int64(len(raw)-1), DecodeLimits{MaxHeaders: 1}); !errors.Is(err, ErrBundleTooLarge) {
			t.Fatal("byte refusal no longer precedes count decoding", err)
		}
		var count *BundleCountLimitError
		if _, err := LoadHeaderBundleWithLimits(path, int64(len(raw)), DecodeLimits{MaxHeaders: 1}); !errors.As(err, &count) {
			t.Fatal("allocation hint bypassed the count limit", err)
		}
	})
}

func FuzzSizedBundleRead(f *testing.F) {
	for _, seed := range []struct {
		input string
		limit uint16
		hint  int64
		mode  uint8
	}{{"", 0, 0, 0}, {"abc", 2, 1, 0}, {"abc", 3, 3, 0}, {"{} trailing", 8, -1, 4}, {"[]", 2, math.MaxInt64, 2}, {"abc", 2, 2, 24}} {
		f.Add([]byte(seed.input), seed.limit, seed.hint, seed.mode)
	}
	f.Fuzz(func(t *testing.T, input []byte, limit uint16, hint int64, mode uint8) {
		if len(input) > 8192 {
			return
		}
		maxBytes := int64(limit % 4097)
		if mode&1 != 0 {
			maxBytes = -1
		} else if mode&2 != 0 {
			maxBytes = math.MaxInt64
		}
		// Exercise huge-hint rejection without allocating up to 64 MiB per
		// fuzz iteration when the legacy MaxInt64 cap is selected.
		if hint > 8192 && hint <= maxBundleReadHintBytes {
			hint = maxBundleReadHintBytes + 1
		}
		terminal := io.EOF
		if mode&8 != 0 {
			terminal = io.ErrUnexpectedEOF
		}
		checkBundleReadReference(t, input, maxBytes, hint, mode&4 != 0, mode&16 != 0, terminal)
	})
}
