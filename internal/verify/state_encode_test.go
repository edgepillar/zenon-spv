package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// The preceding whole-object encoder is an independent byte-format reference.
// It is deliberately not implemented through the incremental writer.
func wholePersistedStateEncoding(w io.Writer, body persistedState) error {
	encoder := json.NewEncoder(&limitedStateWriter{destination: w, remaining: MaxStateFileBytes})
	encoder.SetIndent("", "  ")
	return encoder.Encode(body)
}

func stateEncodingBody(count int) persistedState {
	body := persistedState{Version: retentionStateFileVersion,
		Genesis:  GenesisTrustRoot{ChainID: 3, Height: 100, HeaderHash: chain.Hash{1}},
		Capacity: max(count, 1), Window: make(retainedHeaderWindow, count)}
	for i := range body.Window {
		body.Window[i] = chain.Header{Version: uint64(1 + i%2), ChainIdentifier: 3,
			HeaderHash: chain.Hash{byte(i), 1}, PreviousHash: chain.Hash{byte(i - 1)},
			Height: uint64(101 + i), TimestampUnix: uint64(1700000000 + i),
			DataHash: chain.Hash{2}, ContentHash: chain.Hash{3}, ChangesHash: chain.Hash{4},
			PublicKey: bytes.Repeat([]byte{byte(i)}, 32), Signature: bytes.Repeat([]byte{byte(i + 1)}, 64),
			NextFusionPrice: ^uint64(0), NextWorkPrice: uint64(i)}
	}
	return body
}

func TestPersistedStateEncodingMatchesWholeObject(t *testing.T) {
	for _, count := range []int{0, 1, 16, 256, MaxRetainHeaders} {
		for _, version := range []uint32{stateFileVersion, profileStateFileVersion, retentionStateFileVersion} {
			for _, source := range []string{"", "<>&\"\\\n\t\u2028\u2029\ufffd", string([]byte{0xff, 0, 0xfe})} {
				t.Run(fmt.Sprintf("K%d/version%d/source%q", count, version, source), func(t *testing.T) {
					body := stateEncodingBody(count)
					body.Version = version
					if version != stateFileVersion {
						body.ProtocolProfile = &ProtocolProfile{Version: 1, Anchor: body.Genesis,
							V2FromHeight: 102, ValidThrough: ^uint64(0), Source: source}
					}
					if count > 0 {
						body.Window[0].PublicKey, body.Window[0].Signature = nil, []byte{}
					}
					var want, got bytes.Buffer
					if err := wholePersistedStateEncoding(&want, body); err != nil {
						t.Fatal(err)
					}
					before, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					if err := encodePersistedState(&got, body); err != nil || !bytes.Equal(got.Bytes(), want.Bytes()) {
						t.Fatalf("persisted bytes differ: error=%v lengths=%d/%d", err, got.Len(), want.Len())
					}
					after, err := json.Marshal(body)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("encoding mutated the source", err)
					}
				})
			}
		}
	}
	for _, window := range []retainedHeaderWindow{nil, {}} {
		body := stateEncodingBody(0)
		body.Window = window
		var want, got bytes.Buffer
		if err := wholePersistedStateEncoding(&want, body); err != nil {
			t.Fatal(err)
		}
		if err := encodePersistedState(&got, body); err != nil || !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatal("empty/null window bytes changed", err)
		}
		var decoded persistedState
		if err := json.Unmarshal(got.Bytes(), &decoded); err != nil || !reflect.DeepEqual(window, decoded.Window) {
			t.Fatal("empty/null window shape changed", err)
		}
	}
}

type stateEncodingFailureWriter struct {
	remaining int
	err       error
	short     bool
	written   int
}

func (w *stateEncodingFailureWriter) Write(raw []byte) (int, error) {
	n := min(len(raw), w.remaining)
	w.remaining -= n
	w.written += n
	if n < len(raw) {
		if w.short {
			return n, nil
		}
		return n, w.err
	}
	return n, nil
}

func TestPersistedStateEncodingWriterFailures(t *testing.T) {
	body := stateEncodingBody(256)
	var complete bytes.Buffer
	if err := wholePersistedStateEncoding(&complete, body); err != nil {
		t.Fatal(err)
	}
	fault := errors.New("injected state destination failure")
	for _, limit := range []int{0, 1, (32 << 10) - 1, 32 << 10, (32 << 10) + 1, complete.Len() - 1} {
		for _, short := range []bool{false, true} {
			t.Run(fmt.Sprintf("after%d/short%t", limit, short), func(t *testing.T) {
				w := &stateEncodingFailureWriter{remaining: limit, err: fault, short: short}
				want := fault
				if short {
					want = io.ErrShortWrite
				}
				if err := encodePersistedState(w, body); !errors.Is(err, want) || w.written > limit {
					t.Fatalf("destination failure lost: error=%v written=%d limit=%d", err, w.written, limit)
				}
			})
		}
	}
	for _, limit := range []int64{0, int64(complete.Len() - 1), int64(complete.Len()), int64(complete.Len() + 1)} {
		w := &limitedStateWriter{destination: io.Discard, remaining: limit}
		err := encodePersistedState(w, body)
		if (err == nil) != (limit >= int64(complete.Len())) || err != nil && !errors.Is(err, ErrStateFileTooLarge) {
			t.Fatal("exact output-cap boundary changed", limit, err)
		}
	}
}

func TestPersistedStateEncodingGlobalByteCap(t *testing.T) {
	body := stateEncodingBody(0)
	body.ProtocolProfile = &ProtocolProfile{Source: strings.Repeat("x", int(MaxStateFileBytes))}
	if err := encodePersistedState(io.Discard, body); !errors.Is(err, ErrStateFileTooLarge) {
		t.Fatal("global persisted byte cap was lost", err)
	}
}

func TestPersistedStateEncodingLargeMetadata(t *testing.T) {
	body := stateEncodingBody(16)
	body.ProtocolProfile = &ProtocolProfile{Version: 1, Anchor: body.Genesis,
		V2FromHeight: 102, ValidThrough: 200, Source: strings.Repeat("x", 64<<10)}
	var want, got bytes.Buffer
	if err := wholePersistedStateEncoding(&want, body); err != nil {
		t.Fatal(err)
	}
	if err := encodePersistedState(&got, body); err != nil || !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatal("large metadata bytes changed", err)
	}
	// A metadata value larger than the output buffer can take bufio's direct
	// write path. Even a writer that violates the short-write contract must
	// terminate with an error rather than repeatedly making zero progress.
	fault := errors.New("injected large metadata destination failure")
	for _, limit := range []int{0, 1, (32 << 10) - 1, 32 << 10, (32 << 10) + 1, (64 << 10) - 1, 64 << 10, want.Len() - 1} {
		for _, short := range []bool{false, true} {
			t.Run(fmt.Sprintf("after%d/short%t", limit, short), func(t *testing.T) {
				w := &stateEncodingFailureWriter{remaining: limit, err: fault, short: short}
				expected := fault
				if short {
					expected = io.ErrShortWrite
				}
				if err := encodePersistedState(w, body); !errors.Is(err, expected) || w.written > limit {
					t.Fatalf("large destination failure lost: error=%v written=%d limit=%d", err, w.written, limit)
				}
			})
		}
	}
}

func BenchmarkPersistedStateEncoding(b *testing.B) {
	for _, count := range []int{16, 256, MaxRetainHeaders} {
		body := stateEncodingBody(count)
		var encoded bytes.Buffer
		if err := wholePersistedStateEncoding(&encoded, body); err != nil {
			b.Fatal(err)
		}
		for _, implementation := range []struct {
			name   string
			encode func(io.Writer, persistedState) error
		}{{"whole-object", wholePersistedStateEncoding}, {"bounded", encodePersistedState}} {
			b.Run(fmt.Sprintf("K%d/%s", count, implementation.name), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(encoded.Len()))
				for range b.N {
					if err := implementation.encode(io.Discard, body); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
