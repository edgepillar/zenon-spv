package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

func TestProducerScheduleTerminalHeight(t *testing.T) {
	coverage := []ProducerCoverage{{FromHeight: math.MaxUint64 - 1, ThroughHeight: math.MaxUint64}}
	entries := []ProducerEntry{{Height: math.MaxUint64 - 1}, {Height: math.MaxUint64}}
	s, err := NewProducerSchedule(3, coverage, entries, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := s.LookupEntry(math.MaxUint64); !ok || e.Height != math.MaxUint64 {
		t.Fatal("terminal height lost from validated schedule")
	}
	if _, ok := s.LookupEntry(0); ok {
		t.Fatal("terminal height wrapped into zero")
	}
}

func TestProducerScheduleRangeLookup(t *testing.T) {
	coverage := []ProducerCoverage{{0, 2}, {3, 5}, {17, 17}, {math.MaxUint64 - 1, math.MaxUint64}}
	heights := []uint64{0, 1, 2, 3, 4, 5, 17, math.MaxUint64 - 1, math.MaxUint64}
	entries := make([]ProducerEntry, len(heights))
	want := make(map[uint64]ProducerEntry, len(heights))
	for i, height := range heights {
		entry := ProducerEntry{Height: height, TimestampUnix: uint64(i + 100)}
		entry.ProducingAddr[1] = byte(i + 1)
		entries[i] = entry
		want[height] = entry
	}
	s, err := NewProducerSchedule(3, coverage, entries, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	probes := append(heights, 6, 16, 18, math.MaxUint64-2)
	for _, height := range probes {
		entry, present := s.LookupEntry(height)
		expected, covered := want[height]
		if present != covered || entry != expected {
			t.Fatalf("height %d: got %+v/%t, want %+v/%t", height, entry, present, expected, covered)
		}
	}
}

func BenchmarkProducerScheduleValidatedIndex(b *testing.B) {
	for _, test := range []struct {
		name  string
		width int
	}{
		{"contiguous", MaxProducerScheduleEntries},
		{"gapped", 1000},
		{"singletons", 1},
	} {
		b.Run(test.name, func(b *testing.B) {
			const count = MaxProducerScheduleEntries
			coverage := make([]ProducerCoverage, 0, count/test.width)
			entries := make([]ProducerEntry, count)
			for first := 0; first < count; first += test.width {
				last := min(first+test.width, count)
				startHeight := uint64(first + first/test.width + 1)
				coverage = append(coverage, ProducerCoverage{startHeight, startHeight + uint64(last-first-1)})
				for i := first; i < last; i++ {
					entries[i].Height = startHeight + uint64(i-first)
					entries[i].TimestampUnix = uint64(i + 100)
				}
			}
			schedule := ProducerSchedule{
				ChainID: 3, Coverage: coverage, Entries: entries,
				ScheduleHash: computeScheduleHash(3, coverage, entries),
			}
			b.Run("validate", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if err := schedule.Validate(); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("lookup", func(b *testing.B) {
				if err := schedule.Validate(); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				next := 0
				for b.Loop() {
					expected := entries[next]
					if got, ok := schedule.LookupEntry(expected.Height); !ok || got != expected {
						b.Fatal("lookup did not return the selected entry")
					}
					next = (next + 7919) % count
				}
			})
		})
	}
}

func TestProducerScheduleDenseCoverageBoundaries(t *testing.T) {
	cases := []struct {
		name     string
		coverage []ProducerCoverage
		heights  []uint64
		want     string
	}{
		{"separate ranges", []ProducerCoverage{{2, 3}, {7, 7}}, []uint64{2, 3, 7}, ""},
		{"adjacent ranges", []ProducerCoverage{{2, 3}, {4, 4}}, []uint64{2, 3, 4}, ""},
		{"missing first", []ProducerCoverage{{2, 3}}, []uint64{3}, "height 2 has no entry"},
		{"missing last", []ProducerCoverage{{2, 3}}, []uint64{2}, "height 3 has no entry"},
		{"orphan before", []ProducerCoverage{{2, 3}}, []uint64{1, 2, 3}, "outside declared coverage"},
		{"orphan between", []ProducerCoverage{{2, 2}, {4, 4}}, []uint64{2, 3, 4}, "outside declared coverage"},
		{"orphan after", []ProducerCoverage{{2, 3}}, []uint64{2, 3, 4}, "outside declared coverage"},
		{"huge claim", []ProducerCoverage{{0, math.MaxUint64}}, []uint64{0}, "height 1 has no entry"},
		{"missing terminal", []ProducerCoverage{{math.MaxUint64 - 1, math.MaxUint64}}, []uint64{math.MaxUint64 - 1}, "has no entry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := make([]ProducerEntry, len(tc.heights))
			for i, h := range tc.heights {
				entries[i].Height = h
			}
			_, err := NewProducerSchedule(3, tc.coverage, entries, nil, nil)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestProducerScheduleFailedRevalidationClearsIndex(t *testing.T) {
	s := fixtureSchedule(t, 2)
	s.Entries[0].ProducingAddr[0] ^= 1
	if err := s.Validate(); err == nil {
		t.Fatal("tampered schedule validated")
	}
	if _, ok := s.LookupEntry(101); ok {
		t.Fatal("failed revalidation retained the old authorization index")
	}
}

func TestProducerScheduleCountLimits(t *testing.T) {
	s := fixtureSchedule(t, 2)
	s.Entries = make([]ProducerEntry, MaxProducerScheduleEntries+1)
	if err := s.Validate(); !errors.Is(err, ErrProducerScheduleTooLarge) {
		t.Fatalf("entry limit: %v", err)
	}
	if _, err := NewProducerSchedule(3, s.Coverage, s.Entries, nil, nil); !errors.Is(err, ErrProducerScheduleTooLarge) {
		t.Fatalf("constructor entry limit: %v", err)
	}
	anchor, _, _ := buildChain(t, 1)
	opts := VerifyOptions{Policy: DefaultPolicy(), ProducerAuth: ProducerAuthOptions{
		Mode: ProducerAuthRequired, Authorizer: NewScheduleAuthorizer(s),
	}}
	if _, err := NewVerifiedState(anchor, opts); !errors.Is(err, ErrProducerScheduleTooLarge) {
		t.Fatalf("owned state entry limit: %v", err)
	}
	s.Entries = nil
	s.Coverage = make([]ProducerCoverage, MaxProducerScheduleEntries+1)
	if err := s.Validate(); !errors.Is(err, ErrProducerScheduleTooLarge) {
		t.Fatalf("coverage limit: %v", err)
	}
}

func TestProducerScheduleStrictJSON(t *testing.T) {
	s := fixtureSchedule(t, 2)
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"valid", string(raw), ""},
		{"unknown top-level", `{"unexpected":true,` + string(raw[1:]), "unknown field"},
		{"unknown entry", strings.Replace(string(raw), `"timestamp_unix":`, `"extra":true,"timestamp_unix":`, 1), "invalid entries"},
		{"unknown coverage", strings.Replace(string(raw), `"from_height":`, `"extra":true,"from_height":`, 1), "invalid coverage"},
		{"non-array entries", `{"entries":{}}`, "invalid entries"},
		{"null entries", `{"coverage":[{"from_height":2,"through_height":2}],"entries":null}`, "entries must be non-null"},
		{"trailing object", string(raw) + `{}`, "trailing JSON"},
		{"trailing garbage", string(raw) + `x`, "trailing JSON"},
		{"null", `null`, "expected an object"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeProducerSchedule(strings.NewReader(tc.raw), int64(len(tc.raw)))
			if tc.want != "" {
				if got != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("want %q, got schedule=%v err=%v", tc.want, got != nil, err)
				}
				return
			}
			if err != nil || got.ScheduleHash != s.ScheduleHash {
				t.Fatalf("valid schedule at exact byte limit: %v", err)
			}
			if _, ok := got.LookupEntry(101); !ok {
				t.Fatal("loaded schedule has no authorization index")
			}
		})
	}
}

func TestProducerScheduleJSONCountLimit(t *testing.T) {
	// Exercise the production generic count decoder without materializing a
	// million fully populated signed-authority rows. Empty authority rows are
	// now structurally invalid and fail before the count cap is reached.
	raw := `[` + strings.Repeat(`{},`, MaxProducerScheduleEntries) + `{}]`
	var rows []struct{}
	fields := func(*struct{}) map[string]any { return nil }
	d := json.NewDecoder(strings.NewReader(raw))
	err := decodeScheduleRows(d, &rows, "entries", MaxProducerScheduleEntries, fields)
	if rows != nil || !errors.Is(err, ErrProducerScheduleTooLarge) {
		t.Fatalf("JSON entry limit: published=%t err=%v", rows != nil, err)
	}

	// The first row outside the limit must never reach the row decoder.
	d = json.NewDecoder(strings.NewReader(`[{},false]`))
	err = decodeScheduleRows(d, &rows, "entries", 1, fields)
	if rows != nil || !errors.Is(err, ErrProducerScheduleTooLarge) {
		t.Fatalf("JSON row decoded beyond limit: published=%t err=%v", rows != nil, err)
	}
}

func TestProducerScheduleRowDecoderBoundaries(t *testing.T) {
	schedule := fixtureSchedule(t, 2)
	first, err := json.Marshal(schedule.Entries[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(schedule.Entries[1])
	if err != nil {
		t.Fatal(err)
	}
	escaped := strings.Replace(string(first), `"height"`, `"he\u0069ght"`, 1)
	t.Run("shared object boundary", func(t *testing.T) {
		var standalone ProducerEntry
		if err := json.Unmarshal([]byte(escaped), &standalone); err != nil || standalone != schedule.Entries[0] {
			t.Fatalf("standalone row changed: %v", err)
		}
		input := `{"entries":[` + escaped + "," + string(second) + `],"following":true}`
		d := json.NewDecoder(iotest.OneByteReader(strings.NewReader(input)))
		if token, err := d.Token(); err != nil || token != json.Delim('{') {
			t.Fatal("expected the enclosing object")
		}
		if token, err := d.Token(); err != nil || token != "entries" {
			t.Fatal("expected the entries field")
		}
		var got []ProducerEntry
		if err := decodeScheduleRows(d, &got, "entries", 2, (*ProducerEntry).requiredJSONFields); err != nil ||
			len(got) != 2 || got[0] != standalone || got[1] != schedule.Entries[1] {
			t.Fatalf("nested rows changed: %v", err)
		}
		if token, err := d.Token(); err != nil || token != "following" {
			t.Fatal("row reader consumed the next field")
		}
	})

	for _, tc := range []struct {
		name  string
		input string
	}{
		{"missing row comma", "[" + escaped + string(second) + "]"},
		{"null second row", "[" + escaped + ",null]"},
		{"missing fields in second row", "[" + escaped + `,{"height":102}]`},
		{"trailing comma", "[" + escaped + ",]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := []ProducerEntry{schedule.Entries[1]}
			d := json.NewDecoder(strings.NewReader(tc.input))
			err := decodeScheduleRows(d, &got, "entries", 2, (*ProducerEntry).requiredJSONFields)
			if !errors.Is(err, errInvalidScheduleJSON) || len(got) != 1 || got[0] != schedule.Entries[1] {
				t.Fatalf("invalid array changed its target: %v", err)
			}
		})
	}
}

func TestProducerScheduleByteLimit(t *testing.T) {
	// A stream may report no file size, or a file may grow after Stat.
	// Inspect at most the limit plus one byte.
	input := bytes.NewReader(bytes.Repeat([]byte{' '}, 8192))
	s, err := decodeProducerSchedule(input, 1024)
	if s != nil || !errors.Is(err, ErrProducerScheduleTooLarge) {
		t.Fatalf("stream limit: schedule=%v err=%v", s != nil, err)
	}
	if got := 8192 - input.Len(); got != 1025 {
		t.Fatalf("read %d bytes, want bounded read of 1025", got)
	}

	path := filepath.Join(t.TempDir(), "oversized-schedule.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// A sparse oversized file exercises the real loader without allocating
	// or decoding a full 256 MiB payload in the test process.
	err = f.Truncate(MaxProducerScheduleFileBytes + 1)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("prepare sparse file: truncate=%v close=%v", err, closeErr)
	}
	if s, err := LoadProducerSchedule(path); s != nil || !errors.Is(err, ErrProducerScheduleTooLarge) {
		t.Fatalf("file limit: schedule=%v err=%v", s != nil, err)
	}
}

func TestProducerScheduleStreamCompletion(t *testing.T) {
	want := fixtureSchedule(t, 2)
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n', '\t')
	for _, reader := range []io.Reader{
		iotest.OneByteReader(bytes.NewReader(raw)),
		stateReadFailure{bytes.NewReader(raw), io.EOF},
	} {
		got, err := decodeProducerSchedule(reader, int64(len(raw)))
		if err != nil || got == nil || got.ScheduleHash != want.ScheduleHash {
			t.Fatalf("complete stream at the exact byte limit: %v", err)
		}
		expected, _ := want.LookupEntry(101)
		if entry, ok := got.LookupEntry(101); !ok || entry != expected {
			t.Fatal("complete stream did not build the expected lookup index")
		}
	}
	failure := errors.New("controlled terminal schedule read error")
	invalid := []byte("{\"unknown\":" + strings.Repeat(" ", 4096))
	for _, tc := range []struct {
		name  string
		input []byte
		limit int
		err   error
		want  error
	}{
		{"invalid object exceeds limit", invalid, 2048, nil, ErrProducerScheduleTooLarge},
		{"drain after early parse failure", invalid, len(invalid), failure, failure},
		{"complete object with read error", raw, len(raw), failure, failure},
		{"overflow probe with read error", raw, len(raw) - 1, failure, failure},
		{"trailing closing token", append(bytes.Clone(raw), ']'), len(raw) + 1, nil, errInvalidScheduleJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := bytes.NewReader(tc.input)
			var reader io.Reader = input
			if tc.err != nil {
				reader = stateReadFailure{input, tc.err}
			}
			got, err := decodeProducerSchedule(reader, int64(tc.limit))
			if got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("unexpected stream outcome: schedule=%v err=%v", got != nil, err)
			}
			if read := len(tc.input) - input.Len(); read != min(len(tc.input), tc.limit+1) {
				t.Fatalf("unexpected bounded stream length: %d", read)
			}
		})
	}
}
