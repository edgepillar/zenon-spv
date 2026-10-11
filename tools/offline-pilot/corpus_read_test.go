package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type corpusReadFixture struct {
	sourceReader
	closeErr error
	closed   bool
}

func (r *corpusReadFixture) Close() error { r.closed = true; return r.closeErr }

func TestCorpusMemberReadContract(t *testing.T) {
	readFailure, closeFailure := errors.New("PRIVATE_CORPUS_READ_FAILURE"), errors.New("PRIVATE_CORPUS_CLOSE_FAILURE")
	tests := []struct {
		name          string
		raw           string
		size          int64
		step          int
		readErr       error
		closeErr      error
		dataError, ok bool
	}{
		{"empty", "", 0, 1, io.EOF, nil, false, true},
		{"complete", "corpus", 6, 32, io.EOF, nil, false, true},
		{"short_reads", "corpus", 6, 1, io.EOF, nil, false, true},
		{"shrink", "corpus", 7, 1, io.EOF, nil, false, false},
		{"growth", "corpus!", 6, 1, io.EOF, nil, false, false},
		{"data_and_error", "corpus", 6, 32, readFailure, nil, true, false},
		{"probe_error", "corpus", 6, 1, readFailure, nil, false, false},
		{"close_error", "corpus", 6, 1, io.EOF, closeFailure, false, false},
		{"read_and_close_error", "corpus", 6, 1, readFailure, closeFailure, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := &corpusReadFixture{sourceReader{[]byte(tc.raw), tc.step, tc.readErr, tc.dataError}, tc.closeErr, false}
			digest, err := corpusDigest(input, tc.size, make([]byte, 3))
			if !input.closed || (err == nil) != tc.ok || (!tc.ok && digest != "") {
				t.Fatal("failed corpus capture returned a digest or left its input open")
			}
			if tc.ok {
				expected := sha256.Sum256([]byte(tc.raw))
				if digest != hex.EncodeToString(expected[:]) {
					t.Fatal("corpus capture changed raw SHA-256 bytes")
				}
			}
			if tc.name == "read_and_close_error" && !errors.Is(err, readFailure) {
				t.Fatal("close failure replaced the actual read failure")
			}
		})
	}
	t.Log("offline-pilot-corpus-read-controls {\"schema_version\":1,\"controls\":9,\"complete_reads\":3,\"refusals\":6,\"inputs_closed\":true}")
}

func TestCorpusPinnedHashes(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	var historical []corpusRecord
	for _, path := range corpusPaths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("cannot read pinned node-derived corpus")
		}
		// Independent prior full-buffer SHA-256, without path/length encoding.
		digest := sha256.Sum256(raw)
		historical = append(historical, corpusRecord{path, hex.EncodeToString(digest[:])})
	}
	actual, err := captureCorpus()
	if err != nil || len(actual) != 7 || !reflect.DeepEqual(actual, historical) {
		t.Fatal("streamed corpus changed fixed path order or pinned raw hashes")
	}
	t.Log("offline-pilot-corpus-pinned-hashes {\"schema_version\":1,\"fixed_paths\":7,\"historical_raw_hashes_and_order_matched\":true}")
}

func TestCorpusStreamAndBounds(t *testing.T) {
	t.Chdir(t.TempDir())
	paths := []string{"first.json", "second.json", "empty.json"}
	values := [][]byte{{0, 255, '\n', 128}, []byte("abc"), {}}
	for i, path := range paths {
		if os.WriteFile(path, values[i], 0600) != nil {
			t.Fatal("cannot prepare raw corpus bytes")
		}
	}
	var opened []*os.File
	open := func(path string) (*os.File, error) {
		f, err := openSourceInput(path)
		if err == nil {
			opened = append(opened, f)
		}
		return f, err
	}
	assertClosed := func() {
		t.Helper()
		for _, f := range opened {
			if _, err := f.Stat(); err == nil {
				t.Fatal("corpus descriptor remained open")
			}
		}
		opened = nil
	}
	actual, err := hashCorpusInputs(paths, open)
	if err != nil || len(actual) != len(paths) {
		t.Fatal("raw corpus bytes were refused")
	}
	for i, record := range actual {
		expected := sha256.Sum256(values[i])
		if record.Path != paths[i] || record.SHA256 != hex.EncodeToString(expected[:]) {
			t.Fatal("corpus path order or non-text raw hash changed")
		}
	}
	assertClosed()
	resize := func(size int64) {
		t.Helper()
		if os.Truncate(paths[0], size) != nil {
			t.Fatal("cannot resize corpus member")
		}
	}
	resize(maxCorpusBytes - 3)
	if records, err := hashCorpusInputs(paths, open); err != nil || len(records) != 3 || len(opened) != 3 {
		t.Fatal("exact corpus aggregate ceiling was refused")
	}
	assertClosed()
	resize(maxCorpusBytes - 2)
	if records, err := hashCorpusInputs(paths, open); err == nil || records != nil || len(opened) != 1 {
		t.Fatal("corpus aggregate overflow opened the later member or yielded partial hashes")
	}
	assertClosed()
	resize(maxCorpusBytes + 1)
	if records, err := hashCorpusInputs(paths, open); err == nil || records != nil || len(opened) != 0 {
		t.Fatal("oversized corpus member was opened")
	}
	resize(4)
	if os.Mkdir("directory.json", 0700) != nil {
		t.Fatal("cannot prepare nonregular corpus member")
	}
	for _, later := range []string{"PRIVATE_MISSING.json", "directory.json"} {
		if records, err := hashCorpusInputs([]string{paths[0], later}, open); err == nil || records != nil || len(opened) != 1 {
			t.Fatal("failed later member yielded a partial corpus")
		}
		assertClosed()
	}
	failLater := func(path string) (*os.File, error) {
		if path == paths[1] {
			return nil, errors.New("PRIVATE_CORPUS_OPEN_FAILURE")
		}
		return open(path)
	}
	if records, err := hashCorpusInputs(paths, failLater); err == nil || records != nil || len(opened) != 1 {
		t.Fatal("later open failure yielded partial hashes")
	}
	assertClosed()
	t.Log("offline-pilot-corpus-stream-controls {\"schema_version\":1,\"aggregate_ceiling_bytes\":67108864,\"shared_buffer_bytes\":32768,\"exact_ceiling_passed\":true,\"raw_nontext_hashes_matched\":true,\"refusals\":5,\"descriptors_closed\":true}")
}

// Retain one complete result in both benchmark modes, as captureCorpus returns
// the seven records to its caller. Do not compare an elided buffered result.
var corpusBenchmarkResult []corpusRecord

func priorBufferedCorpus(paths []string) ([]corpusRecord, error) {
	corpus := make([]corpusRecord, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(raw)
		corpus = append(corpus, corpusRecord{path, hex.EncodeToString(digest[:])})
	}
	return corpus, nil
}

func BenchmarkCorpusHash(b *testing.B) {
	var pinned [][]byte
	for _, path := range corpusPaths {
		raw, err := os.ReadFile(filepath.Join("..", "..", path))
		if err != nil {
			b.Fatal("cannot read pinned corpus shape")
		}
		pinned = append(pinned, raw)
	}
	for _, shape := range []struct {
		name string
		size int
	}{{"pinned_corpus", 0}, {"one_MiB_member", 1 << 20}, {"eight_MiB_member", 8 << 20}} {
		b.Run(shape.name, func(b *testing.B) {
			dir := b.TempDir()
			var paths []string
			var total int64
			for i, path := range corpusPaths {
				raw := pinned[i]
				if i == 0 && shape.size != 0 {
					raw = bytes.Repeat([]byte{'x'}, shape.size)
				}
				name := filepath.Join(dir, filepath.Base(path))
				if os.WriteFile(name, raw, 0600) != nil {
					b.Fatal("cannot prepare seven corpus members")
				}
				paths, total = append(paths, name), total+int64(len(raw))
			}
			buffered, bufferedErr := priorBufferedCorpus(paths)
			streamed, streamedErr := hashCorpusInputs(paths, openSourceInput)
			if bufferedErr != nil || streamedErr != nil || !reflect.DeepEqual(buffered, streamed) {
				b.Fatal("corpus benchmark modes disagree on raw hashes")
			}
			for _, mode := range []string{"prior_buffered", "streamed"} {
				b.Run(mode, func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(total)
					for b.Loop() {
						var err error
						if mode == "streamed" {
							corpusBenchmarkResult, err = hashCorpusInputs(paths, openSourceInput)
						} else {
							corpusBenchmarkResult, err = priorBufferedCorpus(paths)
						}
						if err != nil || len(corpusBenchmarkResult) != len(paths) {
							b.Fatal("corpus capture observation was incomplete")
						}
					}
				})
			}
		})
	}
}
