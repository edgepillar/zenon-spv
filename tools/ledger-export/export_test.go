// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"runtime"
	"strings"
	"testing"
)

type pair struct{ key, value []byte }
type fakeIterator struct {
	rows         []pair
	at, released int
	failure      error
	panicRelease bool
}

func (i *fakeIterator) Next() bool    { i.at++; return i.at <= len(i.rows) }
func (i *fakeIterator) Key() []byte   { return i.rows[i.at-1].key }
func (i *fakeIterator) Value() []byte { return i.rows[i.at-1].value }
func (i *fakeIterator) Error() error  { return i.failure }
func (i *fakeIterator) Release() {
	i.released++
	if i.panicRelease {
		panic("private backend text")
	}
}

type fakeSnapshot struct {
	iterator        *fakeIterator
	metadata        []byte
	calls, released int
	getFailure      bool
	changedAtEnd    bool
	panicRelease    bool
}

func (v *fakeSnapshot) Get(key []byte) ([]byte, error) {
	v.calls++
	if !bytes.Equal(key, []byte{0x55, 0}) {
		panic("unexpected identity lookup")
	}
	if v.getFailure {
		return nil, errors.New("private path")
	}
	if v.changedAtEnd && v.calls > 1 {
		return []byte{0}, nil
	}
	return v.metadata, nil
}
func (v *fakeSnapshot) Iterator() rawIterator { return v.iterator }
func (v *fakeSnapshot) Release() {
	v.released++
	if v.panicRelease {
		panic("private release text")
	}
}

type fakeStore struct {
	view                                  *fakeSnapshot
	closed                                int
	openFailure, closeFailure, panicClose bool
}

func (d *fakeStore) Snapshot() (rawSnapshot, error) {
	if d.openFailure {
		return nil, errors.New("private snapshot path")
	}
	return d.view, nil
}
func (d *fakeStore) Close() error {
	d.closed++
	if d.panicClose {
		panic("private close path")
	}
	if d.closeFailure {
		return errors.New("private close path")
	}
	return nil
}

func unhex(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func selected() selection { return selection{strings.Repeat("11", 32), 3000, strings.Repeat("22", 32)} }

// Independent literal from the previously captured node schema and byte oracle:
// HashHeightProto{HashProto{hash=0x11[32]}, height=3000}, with existence marker.
func metadata(t *testing.T) []byte { return unhex(t, "000a220a20"+strings.Repeat("11", 32)+"10b817") }
func fixture(t *testing.T) *fakeStore {
	meta := metadata(t)
	return &fakeStore{view: &fakeSnapshot{metadata: meta, iterator: &fakeIterator{rows: []pair{
		{[]byte{0x55, 0}, meta}, {[]byte{0x55, 'a'}, []byte{0}}, {[]byte{0x55, 'b'}, make([]byte, 33)}, {[]byte{0x55, 'c'}, nil},
	}}}}
}
func literalStream(t *testing.T) []byte {
	return unhex(t, "01010027"+hex.EncodeToString(metadata(t)[1:])+"0101610001016220"+strings.Repeat("00", 32))
}

func TestIdentifierUsesNodeProtobuf(t *testing.T) {
	got, err := selected().physicalIdentifier()
	if err != nil || !bytes.Equal(got, metadata(t)) {
		t.Fatalf("identifier: %x %v", got, err)
	}
	for _, test := range []struct {
		height uint64
		suffix string
	}{{0, ""}, {127, "107f"}, {128, "108001"}, {math.MaxUint64, "10ffffffffffffffffff01"}} {
		s := selected()
		s.Height = test.height
		got, err := s.physicalIdentifier()
		if err != nil || hex.EncodeToString(got) != "000a220a20"+strings.Repeat("11", 32)+test.suffix {
			t.Fatal("protobuf height boundary")
		}
	}
	t.Run("source-genesis-9c71", func(t *testing.T) {
		// Selected source-genesis identifier, independently matched against the
		// original node frontier and the retained complete export stream.
		s := selection{Hash: "9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0", Height: 1, Provenance: selected().Provenance}
		want := unhex(t, "000a220a209e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb01001")
		got, err := s.physicalIdentifier()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("source-genesis identifier bytes changed")
		}
	})
}

func TestLiteralStreamKeepsEmptyAndZeroAndOmitsTombstone(t *testing.T) {
	db := fixture(t)
	var out bytes.Buffer
	stats, err := exportStore(context.Background(), db, &out, selected(), defaults)
	if err != nil || !bytes.Equal(out.Bytes(), literalStream(t)) {
		t.Fatalf("stream: %x %v", out.Bytes(), err)
	}
	digest := sha256.Sum256(literalStream(t))
	if stats.Records != 3 || stats.Scanned != 4 || stats.Tombstones != 1 || stats.PresentEmpty != 1 || stats.OutputBytes != 83 || stats.ScannedBytes != 82 || stats.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("statistics: %+v", stats)
	}
	if db.closed != 1 || db.view.released != 1 || db.view.iterator.released != 1 || db.view.calls != 2 {
		t.Fatal("owned resources not released exactly once")
	}
}

func TestWrongIdentifierWritesNothing(t *testing.T) {
	for _, change := range []func(*selection){func(s *selection) { s.Height++ }, func(s *selection) { s.Hash = strings.Repeat("00", 32) }} {
		db := fixture(t)
		s := selected()
		change(&s)
		var out bytes.Buffer
		_, err := exportStore(context.Background(), db, &out, s, defaults)
		if err == nil || out.Len() != 0 || db.closed != 1 || db.view.released != 1 || db.view.iterator.released != 0 {
			t.Fatal("wrong full identifier accepted")
		}
	}
}

func TestMetadataMustBeEnumeratedAndMatchLookup(t *testing.T) {
	for _, mode := range []string{"missing", "tombstone", "changed", "flat"} {
		t.Run(mode, func(t *testing.T) {
			db := fixture(t)
			switch mode {
			case "missing":
				db.view.iterator.rows = db.view.iterator.rows[1:]
			case "tombstone":
				db.view.iterator.rows[0].value = nil
			case "changed":
				db.view.changedAtEnd = true
			case "flat":
				db.view.metadata = append([]byte{0}, make([]byte, 40)...)
			}
			stats, err := exportStore(context.Background(), db, io.Discard, selected(), defaults)
			if err == nil || stats != (statistics{}) || db.closed != 1 || db.view.released != 1 {
				t.Fatal("inconsistent metadata accepted")
			}
		})
	}
}

func TestUnknownMarkersNamespacesAndKeyOrderRefuse(t *testing.T) {
	for _, mode := range []string{"marker", "namespace", "duplicate", "descending"} {
		t.Run(mode, func(t *testing.T) {
			db := fixture(t)
			rows := db.view.iterator.rows
			switch mode {
			case "marker":
				rows[1].value = []byte{1}
			case "namespace":
				rows[1].key = []byte{0x66, 'a'}
			case "duplicate":
				rows[2].key = []byte{0x55, 'a'}
			case "descending":
				rows[2].key = []byte{0x55, 0}
			}
			stats, err := exportStore(context.Background(), db, io.Discard, selected(), defaults)
			if err == nil || stats != (statistics{}) || db.view.iterator.released != 1 {
				t.Fatal("malformed physical frontier accepted")
			}
		})
	}
}

func TestEveryIndependentBudgetIsEnforced(t *testing.T) {
	for _, mode := range []string{"wire", "records", "scan-bytes", "scan-records", "key", "value"} {
		t.Run(mode, func(t *testing.T) {
			db := fixture(t)
			caps := defaults
			switch mode {
			case "wire":
				caps.OutputBytes = 82
			case "records":
				caps.Records = 2
			case "scan-bytes":
				caps.ScanBytes = 81
			case "scan-records":
				caps.ScanRecords = 3
			case "key":
				db.view.iterator.rows[1].key = []byte{0x55, 'a', 'a'}
				caps.KeyBytes = 1
			case "value":
				caps.ValueBytes = 38
			}
			stats, err := exportStore(context.Background(), db, io.Discard, selected(), caps)
			if err == nil || stats != (statistics{}) || db.closed != 1 || db.view.released != 1 {
				t.Fatal("measurement budget not enforced")
			}
		})
	}
}

func TestInvalidLimitsRefuseBeforeIterator(t *testing.T) {
	for _, field := range []int{0, 1, 2, 3, 4, 5} {
		for _, n := range []uint64{0, math.MaxUint64} {
			db := fixture(t)
			caps := defaults
			fields := []*uint64{&caps.OutputBytes, &caps.Records, &caps.ScanBytes, &caps.ScanRecords, &caps.KeyBytes, &caps.ValueBytes}
			*fields[field] = n
			if _, err := exportStore(context.Background(), db, io.Discard, selected(), caps); err == nil || db.view.calls != 0 || db.view.iterator.released != 0 || db.view.released != 1 || db.closed != 1 {
				t.Fatal("invalid caps reached iterator")
			}
		}
	}
}

type badWriter struct{ mode string }

func (w badWriter) Write(raw []byte) (int, error) {
	switch w.mode {
	case "short":
		return 0, nil
	case "error":
		return 0, errors.New("private writer path")
	case "panic":
		panic("private writer path")
	}
	return len(raw) + 1, nil
}

func TestWriterFailuresPreserveUnknownAndRelease(t *testing.T) {
	for _, mode := range []string{"short", "error", "panic", "invalid-count"} {
		t.Run(mode, func(t *testing.T) {
			db := fixture(t)
			stats, err := exportStore(context.Background(), db, badWriter{mode}, selected(), defaults)
			if err == nil || stats != (statistics{}) || db.view.iterator.released != 1 || db.view.released != 1 || db.closed != 1 {
				t.Fatal("writer failure cleanup")
			}
		})
	}
}

func TestBackendErrorsAndPanicsAlwaysClose(t *testing.T) {
	for _, mode := range []string{"open", "get", "iterator", "close", "iterator-panic", "snapshot-panic", "close-panic"} {
		t.Run(mode, func(t *testing.T) {
			db := fixture(t)
			switch mode {
			case "open":
				db.openFailure = true
			case "get":
				db.view.getFailure = true
			case "iterator":
				db.view.iterator.failure = errors.New("private iterator path")
			case "close":
				db.closeFailure = true
			case "iterator-panic":
				db.view.iterator.panicRelease = true
			case "snapshot-panic":
				db.view.panicRelease = true
			case "close-panic":
				db.panicClose = true
			}
			stats, err := exportStore(context.Background(), db, io.Discard, selected(), defaults)
			if err == nil || stats != (statistics{}) || db.closed != 1 {
				t.Fatal("backend failure became success")
			}
			if mode != "open" && db.view.released != 1 {
				t.Fatal("snapshot leaked")
			}
		})
	}
}

type cancelWriter struct{ cancel context.CancelFunc }

func (w cancelWriter) Write(raw []byte) (int, error) { w.cancel(); return len(raw), nil }
func TestCancellationBeforeAndDuringOutput(t *testing.T) {
	for _, before := range []bool{false, true} {
		db := fixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		if before {
			cancel()
		}
		stats, err := exportStore(ctx, db, cancelWriter{cancel}, selected(), defaults)
		cancel()
		if err == nil || stats != (statistics{}) || db.closed != 1 || db.view.released != 1 {
			t.Fatal("cancellation accepted")
		}
	}
}

type boundedSink struct {
	max   int
	bytes uint64
}

func (w *boundedSink) Write(raw []byte) (int, error) {
	if len(raw) > w.max {
		w.max = len(raw)
	}
	w.bytes += uint64(len(raw))
	return len(raw), nil
}
func TestLargeValueHasBoundedWritesAndEncoderAllocations(t *testing.T) {
	db := fixture(t)
	db.view.iterator.rows = []pair{{[]byte{0x55, 0}, metadata(t)}, {[]byte{0x55, 'z'}, make([]byte, (32<<20)+1)}}
	caps := defaults
	caps.ValueBytes = 32 << 20
	caps.ScanBytes = 64 << 20
	caps.OutputBytes = 64 << 20
	sink := new(boundedSink)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	stats, err := exportStore(context.Background(), db, sink, selected(), caps)
	runtime.ReadMemStats(&after)
	if err != nil || stats.Records != 2 || sink.max > writeChunk || sink.bytes != stats.OutputBytes || after.TotalAlloc-before.TotalAlloc > 1<<20 {
		t.Fatalf("finite encoder allocation/write bound: %v %+v", err, stats)
	}
	t.Logf("scope=exportStore over a prebuilt fake snapshot, including controlled release/close and excluding fixture construction; logical_value_bytes=%d max_write_request_bytes=%d Go_TotalAlloc_delta_bytes=%d; not total RSS or representative workload", 32<<20, sink.max, after.TotalAlloc-before.TotalAlloc)
}

func TestEmptyLogicalKeyAndLongKeyRemainOrdered(t *testing.T) {
	db := fixture(t)
	long := append([]byte{0x55, 'z'}, make([]byte, 65536)...)
	db.view.iterator.rows = []pair{{[]byte{0x55}, []byte{0}}, {[]byte{0x55, 0}, metadata(t)}, {long, []byte{0, 'v'}}}
	caps := defaults
	caps.KeyBytes = 65537
	sink := new(boundedSink)
	stats, err := exportStore(context.Background(), db, sink, selected(), caps)
	if err != nil || stats.Records != 3 || stats.PresentEmpty != 1 || sink.max > writeChunk {
		t.Fatal("empty or long key lost")
	}
}
