// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"
)

// These rows are a finite encoder workload, not a representative ledger. Each
// generated logical key is z || uint32_be(index), with a present 32-byte value.
func smallRecordStore(tb testing.TB, count int) *fakeStore {
	tb.Helper()
	meta, err := hex.DecodeString("000a220a20" + selected().Hash + "10b817")
	if err != nil {
		tb.Fatal(err)
	}
	rows := make([]pair, 1, count+1)
	rows[0] = pair{[]byte{0x55, 0}, meta}
	value := append([]byte{0}, bytes.Repeat([]byte{0x5a}, 32)...)
	for i := 0; i < count; i++ {
		rows = append(rows, pair{[]byte{0x55, 'z', byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}, value})
	}
	return &fakeStore{view: &fakeSnapshot{metadata: meta, iterator: &fakeIterator{rows: rows}}}
}

func smallRecordWire(tb testing.TB, count int) []byte {
	tb.Helper()
	// Literal put header/key/length and the separately fixed protobuf identifier.
	raw, err := hex.DecodeString("010100270a220a20" + selected().Hash + "10b817")
	if err != nil {
		tb.Fatal(err)
	}
	for i := 0; i < count; i++ {
		raw = append(raw, 1, 5, 'z', byte(i>>24), byte(i>>16), byte(i>>8), byte(i), 32)
		raw = append(raw, bytes.Repeat([]byte{0x5a}, 32)...)
	}
	return raw
}

type measuredWriter struct {
	bytes.Buffer
	calls, maximum int
	failAt         int
	mode           string
	cancel         context.CancelFunc
}

func (w *measuredWriter) Write(raw []byte) (int, error) {
	w.calls++
	if len(raw) > w.maximum {
		w.maximum = len(raw)
	}
	if w.calls == w.failAt {
		switch w.mode {
		case "error":
			return 0, errors.New("private output failure")
		case "short":
			return 0, nil
		case "negative":
			return -1, nil
		case "overflow":
			return len(raw) + 1, nil
		case "panic":
			panic("private output failure")
		}
	}
	n, err := w.Buffer.Write(raw)
	if w.cancel != nil {
		w.cancel()
	}
	return n, err
}

func TestBufferedExportPreservesWireAndBoundsWrites(t *testing.T) {
	for _, count := range []int{0, 1, 1637, 1638, 10000} {
		db, sink := smallRecordStore(t, count), new(measuredWriter)
		want := smallRecordWire(t, count)
		stats, err := exportStore(context.Background(), db, sink, selected(), defaults)
		digest := sha256.Sum256(want)
		writes := (len(want) + writeChunk - 1) / writeChunk
		if err != nil || !bytes.Equal(sink.Bytes(), want) || stats.SHA256 != hex.EncodeToString(digest[:]) ||
			stats.OutputBytes != uint64(len(want)) || stats.Records != uint64(count+1) ||
			sink.calls != writes || sink.maximum > writeChunk ||
			db.closed != 1 || db.view.released != 1 || db.view.iterator.released != 1 {
			t.Fatalf("count=%d writes=%d want=%d bytes=%d: %v %+v", count, sink.calls, writes, sink.Len(), err, stats)
		}
	}
}

func TestBufferedExportDiscardsUnvalidatedTail(t *testing.T) {
	for _, mode := range []string{"iterator", "identifier", "records", "last-value"} {
		t.Run(mode, func(t *testing.T) {
			db, sink := smallRecordStore(t, 2000), new(measuredWriter)
			want := smallRecordWire(t, 2000)
			caps := defaults
			switch mode {
			case "iterator":
				db.view.iterator.failure = errors.New("private iterator failure")
			case "identifier":
				db.view.changedAtEnd = true
			case "records":
				caps.Records = 1800
			case "last-value":
				db.view.iterator.rows[len(db.view.iterator.rows)-1].value = []byte{1}
			}
			stats, err := exportStore(context.Background(), db, sink, selected(), caps)
			if err == nil || stats != (statistics{}) || sink.calls != 1 ||
				!bytes.Equal(sink.Bytes(), want[:writeChunk]) ||
				db.closed != 1 || db.view.released != 1 || db.view.iterator.released != 1 {
				t.Fatal("pending bytes flushed after a refused frontier or incomplete iterator")
			}
		})
	}
}

func TestBufferedExportOutputFailuresRemainUnknown(t *testing.T) {
	for _, position := range []struct {
		name, mode string
		count, at  int
	}{
		{"final-error", "error", 1, 1}, {"full-error", "error", 2000, 1},
		{"tail-error", "error", 2000, 2}, {"tail-short", "short", 2000, 2},
		{"tail-negative", "negative", 2000, 2}, {"tail-overflow", "overflow", 2000, 2},
		{"tail-panic", "panic", 2000, 2},
	} {
		t.Run(position.name, func(t *testing.T) {
			db := smallRecordStore(t, position.count)
			sink := &measuredWriter{failAt: position.at, mode: position.mode}
			stats, err := exportStore(context.Background(), db, sink, selected(), defaults)
			wantReason := "output_write"
			if position.mode == "panic" {
				wantReason = "backend_failure"
			}
			if err == nil || reason(err) != wantReason || stats != (statistics{}) ||
				sink.calls != position.at || sink.Len() != (position.at-1)*writeChunk ||
				db.closed != 1 || db.view.released != 1 || db.view.iterator.released != 1 {
				t.Fatal("buffered write failure accepted or owned resources leaked")
			}
		})
	}
}

func TestBufferedExportCancellationDoesNotFlushTail(t *testing.T) {
	for _, count := range []int{1, 2000} {
		ctx, cancel := context.WithCancel(context.Background())
		db, sink := smallRecordStore(t, count), &measuredWriter{cancel: cancel}
		stats, err := exportStore(ctx, db, sink, selected(), defaults)
		cancel()
		want := smallRecordWire(t, count)
		if len(want) > writeChunk {
			want = want[:writeChunk]
		}
		if err == nil || reason(err) != "canceled" || stats != (statistics{}) || sink.calls != 1 ||
			!bytes.Equal(sink.Bytes(), want) || db.closed != 1 || db.view.released != 1 || db.view.iterator.released != 1 {
			t.Fatal("cancellation became completion or flushed remaining output")
		}
	}
}

// Fixture construction and device opening are outside the timer. Discard scopes
// the encoder/hash cost; the null device adds real write calls, without storing
// another payload. Neither is a database, pipe-backpressure or R1 acceptance test.
func BenchmarkExportSmallRecords(b *testing.B) {
	for _, device := range []bool{false, true} {
		name := "discard"
		var writer io.Writer = io.Discard
		if device {
			name = "null-device"
			file, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
			if err != nil {
				b.Fatal(err)
			}
			defer file.Close()
			writer = file
		}
		b.Run(name, func(b *testing.B) {
			db := smallRecordStore(b, 10000)
			b.SetBytes(400043)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				db.view.iterator.at = 0
				stats, err := exportStore(context.Background(), db, writer, selected(), defaults)
				if err != nil || stats.OutputBytes != 400043 {
					b.Fatal("controlled export did not complete", err)
				}
			}
		})
	}
}
