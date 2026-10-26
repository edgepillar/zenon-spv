// SPDX-License-Identifier: MIT
// Export one selected physical frontier view. This is an R1 measurement tool,
// not a snapshot importer or an authenticated state-proof consumer.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
)

const layout = "zenon-9c71-frontier-v1"
const nodeRevision = "9c71ae82fc983e16f914ae085d4034030c8ebe3b"
const writeChunk = 64 << 10

type refusal string

func (r refusal) Error() string { return string(r) }

type limits struct {
	OutputBytes uint64 `json:"output_bytes"`
	Records     uint64 `json:"records"`
	ScanBytes   uint64 `json:"scan_key_and_encoded_value_bytes"`
	ScanRecords uint64 `json:"scan_records"`
	KeyBytes    uint64 `json:"key_bytes"`
	ValueBytes  uint64 `json:"value_bytes"`
}

var defaults = limits{256 << 20, 2_000_000, 256 << 20, 2_000_000, 1024, 1 << 20}
var hard = limits{16 << 30, 100_000_000, 16 << 30, 100_000_000, 1 << 20, 64 << 20}

func (l limits) valid() bool {
	values := []uint64{l.OutputBytes, l.Records, l.ScanBytes, l.ScanRecords, l.KeyBytes, l.ValueBytes}
	maximum := []uint64{hard.OutputBytes, hard.Records, hard.ScanBytes, hard.ScanRecords, hard.KeyBytes, hard.ValueBytes}
	for i, n := range values {
		if n == 0 || n > maximum[i] {
			return false
		}
	}
	return true
}

type selection struct {
	Hash       string `json:"hash"`
	Height     uint64 `json:"height"`
	Provenance string `json:"provenance_sha256"`
}

func canonicalHash(text string) ([]byte, bool) {
	if len(text) != 64 {
		return nil, false
	}
	raw, err := hex.DecodeString(text)
	return raw, err == nil && len(raw) == 32 && hex.EncodeToString(raw) == text
}

// SetFrontier stores HashHeight.Serialize(), not HashHeight.Bytes(). The
// selected proto3 schema is HashHeight{Hash{bytes[32]}, uint64 height}. Refuse
// other encodings for this layout; this is not a network validity rule.
func (s selection) physicalIdentifier() ([]byte, error) {
	hash, ok := canonicalHash(s.Hash)
	_, provenanceOK := canonicalHash(s.Provenance)
	if !ok || !provenanceOK {
		return nil, refusal("selection")
	}
	out := append([]byte{0, 0x0a, 0x22, 0x0a, 0x20}, hash...)
	if s.Height != 0 {
		var b [10]byte
		out = append(out, 0x10)
		out = append(out, b[:binary.PutUvarint(b[:], s.Height)]...)
	}
	return out, nil
}

type rawIterator interface {
	Next() bool
	Key() []byte
	Value() []byte
	Error() error
	Release()
}

type rawSnapshot interface {
	Get([]byte) ([]byte, error)
	Iterator() rawIterator
	Release()
}

type rawStore interface {
	Snapshot() (rawSnapshot, error)
	Close() error
}

type statistics struct {
	Records      uint64 `json:"records"`
	OutputBytes  uint64 `json:"put_wire_bytes"`
	Scanned      uint64 `json:"scanned_records"`
	ScannedBytes uint64 `json:"scanned_key_and_encoded_value_bytes"`
	Tombstones   uint64 `json:"physical_tombstones_omitted"`
	PresentEmpty uint64 `json:"present_empty_values"`
	SHA256       string `json:"put_stream_sha256"`
}

func addBounded(total *uint64, n, bound uint64, code string) error {
	if n > bound || *total > bound-n {
		return refusal(code)
	}
	*total += n
	return nil
}

func writeAll(ctx context.Context, writer io.Writer, raw []byte) error {
	for len(raw) > 0 {
		if ctx.Err() != nil {
			return refusal("canceled")
		}
		n := len(raw)
		if n > writeChunk {
			n = writeChunk
		}
		written, err := writer.Write(raw[:n])
		if err != nil || written != n {
			return refusal("output_write")
		}
		raw = raw[n:]
	}
	return nil
}

// Normalize an invalid writer count before bufio uses it to move pending bytes.
// The outer write/flush checks still refuse every short or failed write.
type checkedWriter struct{ io.Writer }

func (w checkedWriter) Write(raw []byte) (int, error) {
	n, err := w.Writer.Write(raw)
	if n < 0 || n > len(raw) {
		return 0, io.ErrShortWrite
	}
	return n, err
}

func exportSnapshot(ctx context.Context, view rawSnapshot, writer io.Writer, selected selection, caps limits) (statistics, error) {
	var result statistics
	if !caps.valid() {
		return result, refusal("limits")
	}
	expected, err := selected.physicalIdentifier()
	if err != nil {
		return result, err
	}
	if ctx.Err() != nil {
		return result, refusal("canceled")
	}
	identity, err := view.Get([]byte{0x55, 0})
	if err != nil || !bytes.Equal(identity, expected) {
		return result, refusal("frontier_identifier")
	}
	iterator := view.Iterator()
	if iterator == nil {
		return result, refusal("iterator")
	}
	defer iterator.Release()
	hash := sha256.New()
	out := bufio.NewWriterSize(checkedWriter{io.MultiWriter(writer, hash)}, writeChunk)
	var previous []byte
	var header [21]byte
	var valueLength [10]byte
	havePrevious := false
	sawIdentifier := false
	for iterator.Next() {
		if ctx.Err() != nil {
			return statistics{}, refusal("canceled")
		}
		key, value := iterator.Key(), iterator.Value()
		if len(key) == 0 || key[0] != 0x55 {
			return statistics{}, refusal("frontier_namespace")
		}
		logicalKey := key[1:]
		if bytes.Equal(key, []byte{0x55, 0}) {
			if !bytes.Equal(value, expected) {
				return statistics{}, refusal("frontier_identifier")
			}
			sawIdentifier = true
		}
		if uint64(len(logicalKey)) > caps.KeyBytes {
			return statistics{}, refusal("key_size")
		}
		if len(value) > 0 && (value[0] != 0 || uint64(len(value)-1) > caps.ValueBytes) {
			return statistics{}, refusal("value_encoding_or_size")
		}
		if havePrevious && bytes.Compare(key, previous) <= 0 {
			return statistics{}, refusal("key_order")
		}
		previous = append(previous[:0], key...)
		havePrevious = true
		if err := addBounded(&result.Scanned, 1, caps.ScanRecords, "scan_records"); err != nil {
			return statistics{}, err
		}
		if err := addBounded(&result.ScannedBytes, uint64(len(key))+uint64(len(value)), caps.ScanBytes, "scan_bytes"); err != nil {
			return statistics{}, err
		}
		if len(value) == 0 {
			result.Tombstones++
			continue
		}
		logicalValue := value[1:]
		header[0] = 1
		kn := binary.PutUvarint(header[1:], uint64(len(logicalKey)))
		vn := binary.PutUvarint(valueLength[:], uint64(len(logicalValue)))
		wireBytes := uint64(1+kn+vn) + uint64(len(logicalKey)) + uint64(len(logicalValue))
		if err := addBounded(&result.Records, 1, caps.Records, "records"); err != nil {
			return statistics{}, err
		}
		if err := addBounded(&result.OutputBytes, wireBytes, caps.OutputBytes, "output_bytes"); err != nil {
			return statistics{}, err
		}
		for _, piece := range [][]byte{header[:1+kn], logicalKey, valueLength[:vn], logicalValue} {
			if err := writeAll(ctx, out, piece); err != nil {
				return statistics{}, err
			}
		}
		if len(logicalValue) == 0 {
			result.PresentEmpty++
		}
	}
	if iterator.Error() != nil {
		return statistics{}, refusal("iterator_read")
	}
	if !sawIdentifier {
		return statistics{}, refusal("frontier_identifier")
	}
	identity, err = view.Get([]byte{0x55, 0})
	if err != nil || !bytes.Equal(identity, expected) {
		return statistics{}, refusal("frontier_identifier")
	}
	// No deferred flush: a refused frontier or incomplete iterator must not
	// release the pending tail. Success also requires this last write and a
	// cancellation check after it; store closure remains exportStore's gate.
	if ctx.Err() != nil {
		return statistics{}, refusal("canceled")
	}
	if err := out.Flush(); err != nil {
		return statistics{}, refusal("output_write")
	}
	if ctx.Err() != nil {
		return statistics{}, refusal("canceled")
	}
	result.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return result, nil
}

// Own the store and snapshot through every normal return and panic. Iterator
// release belongs to exportSnapshot. Success is reported only after closure.
func exportStore(ctx context.Context, db rawStore, out io.Writer, selected selection, caps limits) (result statistics, err error) {
	defer func() {
		if recover() != nil {
			result, err = statistics{}, refusal("backend_failure")
		}
	}()
	defer func() {
		if closeErr := db.Close(); closeErr != nil && err == nil {
			result, err = statistics{}, refusal("store_close")
		}
	}()
	view, openErr := db.Snapshot()
	if openErr != nil || view == nil {
		return statistics{}, refusal("snapshot_open")
	}
	defer view.Release()
	return exportSnapshot(ctx, view, out, selected, caps)
}

func reason(err error) string {
	var selected refusal
	if errors.As(err, &selected) {
		return string(selected)
	}
	return "operation_failed"
}
