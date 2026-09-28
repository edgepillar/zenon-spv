package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		{"unknown entry", strings.Replace(string(raw), `"timestamp_unix":`, `"extra":true,"timestamp_unix":`, 1), "unknown field"},
		{"unknown coverage", strings.Replace(string(raw), `"from_height":`, `"extra":true,"from_height":`, 1), "unknown field"},
		{"non-array entries", `{"entries":{}}`, "expected an array"},
		{"null entries", `{"coverage":[{"from_height":2,"through_height":2}],"entries":null}`, "has no entry"},
		{"trailing object", string(raw) + `{}`, "trailing JSON"},
		{"trailing garbage", string(raw) + `x`, "trailing JSON"},
		{"null", `null`, "empty coverage"},
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
	// This small wire input would allocate more than a million structs if
	// the loader checked counts only after a normal json.Unmarshal.
	raw := `{"entries":[` + strings.Repeat(`{},`, MaxProducerScheduleEntries) + `{}]}`
	s, err := decodeProducerSchedule(strings.NewReader(raw), int64(len(raw)))
	if s != nil || !errors.Is(err, ErrProducerScheduleTooLarge) {
		t.Fatalf("JSON entry limit: schedule=%v err=%v", s != nil, err)
	}
}

func TestProducerScheduleByteLimit(t *testing.T) {
	// A stream may report no file size, or a file may grow after Stat. The
	// decoder must stop after the limit plus one byte without parsing it.
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
