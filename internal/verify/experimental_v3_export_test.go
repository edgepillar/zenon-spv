// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestExperimentalV3CheckpointExportRoundTrip(t *testing.T) {
	f := experimentalV3Inputs(t)
	f.profile.Source = "PRIVATE operator provenance"
	state, path, saved := experimentalV3Saved(t, f)
	privateLabel := experimentalV3JSON(t, f.profile.Source)
	publicLabel := experimentalV3JSON(t, experimentalV3ExportSource)
	if bytes.Count(saved, privateLabel) != 1 {
		t.Fatal("original save omitted its selected provenance label")
	}
	var output bytes.Buffer
	if err := state.WriteCheckpoint(&output); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte("PRIVATE")) ||
		!bytes.Equal(output.Bytes(), bytes.Replace(saved, privateLabel, publicLabel, 1)) {
		t.Fatal("export changed bytes beyond the informational provenance label")
	}
	var body experimentalV3File
	if json.Unmarshal(output.Bytes(), &body) != nil || body.Version != 4 || body.Format != experimentalV3StateFormat ||
		body.Context != f.pin || body.Profile.Source != experimentalV3ExportSource {
		t.Fatal("export is not an existing experimental checkpoint")
	}
	digest := sha256.Sum256(output.Bytes())
	loaded, err := DecodePinnedTrustedExperimentalV3State(output.Bytes(), f.profile, f.policy, f.schedule, f.pin, digest)
	if err != nil || loaded.Empty() {
		t.Fatal("export cannot enter the existing pinned trusted import", err)
	}
	selected := f.headers[len(f.headers)-2]
	root, err := loaded.RootAt(selected.Header.Height, selected.Header.HeaderHash, f.pin)
	if err != nil || root != selected.StateRoot {
		t.Fatal("imported checkpoint changed the eligible root", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(saved, after) || state.data.config.profile.Source != f.profile.Source {
		t.Fatal("export rewrote the saved file or immutable configuration", err)
	}
	var repeated bytes.Buffer
	if err := loaded.WriteCheckpoint(&repeated); err != nil || !bytes.Equal(output.Bytes(), repeated.Bytes()) {
		t.Fatal("export/import/export is not byte stable", err)
	}
}

type experimentalCheckpointWriteFunc func([]byte) (int, error)

func (f experimentalCheckpointWriteFunc) Write(raw []byte) (int, error) { return f(raw) }

func TestExperimentalV3CheckpointExportWriteFailures(t *testing.T) {
	f := experimentalV3Inputs(t)
	state := experimentalV3New(t, f)
	result, state := state.Extend(f.headers)
	if result.Outcome != OutcomeAccept {
		t.Fatal(result)
	}
	var before bytes.Buffer
	if err := state.WriteCheckpoint(&before); err != nil {
		t.Fatal(err)
	}
	privateFailure := errors.New("PRIVATE stream failure")
	for _, test := range []struct {
		name  string
		write experimentalCheckpointWriteFunc
		want  error
	}{
		{"short", func(raw []byte) (int, error) { return len(raw) - 1, nil }, io.ErrShortWrite},
		{"negative-count", func([]byte) (int, error) { return -1, nil }, io.ErrShortWrite},
		{"oversized-count", func(raw []byte) (int, error) { return len(raw) + 1, nil }, io.ErrShortWrite},
		{"failed", func([]byte) (int, error) { return 0, privateFailure }, privateFailure},
		{"partial-failed", func(raw []byte) (int, error) { return len(raw) / 2, privateFailure }, privateFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := state.WriteCheckpoint(test.write); !errors.Is(err, test.want) {
				t.Fatal("incomplete output accepted", err)
			}
		})
	}
	if err := state.WriteCheckpoint(nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("nil destination accepted", err)
	}
	var zero ExperimentalV3State
	if err := zero.WriteCheckpoint(io.Discard); !errors.Is(err, ErrUninitializedState) {
		t.Fatal("uninitialized state exported", err)
	}
	// Inject an oversized internal encoding without a database, header corpus or
	// output file. The shared codec must enforce its existing byte cap before IO.
	profile := f.profile
	profile.Source = strings.Repeat("x", int(MaxExperimentalV3StateBytes))
	var bounded bytes.Buffer
	if err := state.encodeExperimentalV3Checkpoint(&bounded, profile); !errors.Is(err, ErrStateFileTooLarge) || bounded.Len() != 0 {
		t.Fatal("encoding cap permitted output", err, bounded.Len())
	}
	var after bytes.Buffer
	if err := state.WriteCheckpoint(&after); err != nil || !bytes.Equal(before.Bytes(), after.Bytes()) {
		t.Fatal("failed output changed the immutable handle", err)
	}
}

func checkpointEncodingFixture(t testing.TB, count int) ExperimentalV3State {
	t.Helper()
	f := experimentalV3RetentionInputs(t, MaxRetainHeaders, MaxRetainHeaders)
	state := experimentalV3New(t, f)
	// Repeat the recorded envelopes to exercise encoding at capacity. This
	// does not construct a contiguous chain or produce any new signatures.
	state.data.headers = make(experimentalV3Window, count)
	for i := range state.data.headers {
		state.data.headers[i] = f.headers[i%len(f.headers)]
	}
	return state
}

func encodeWholeExperimentalV3Checkpoint(destination io.Writer, state ExperimentalV3State, profile ExperimentalV3Profile) error {
	encoder := json.NewEncoder(&limitedStateWriter{
		destination: experimentalV3CompleteWriter{destination}, remaining: MaxExperimentalV3StateBytes,
	})
	encoder.SetIndent("", "  ")
	return encoder.Encode(experimentalV3File{Format: experimentalV3StateFormat, Version: 4,
		Context: state.data.config.context.Fingerprint, Profile: profile,
		Policy: state.data.config.policy, Headers: state.data.headers})
}

func TestExperimentalV3CheckpointWindowEncoding(t *testing.T) {
	for _, test := range []struct {
		name  string
		count int
	}{
		{"empty", 0},
		{"whole", 63},
		{"stream", 64},
		{"capacity", MaxRetainHeaders},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := checkpointEncodingFixture(t, test.count)
			profile := state.data.config.profile
			profile.Source = "Selected <source> & \"operator\""
			var whole, candidate bytes.Buffer
			if err := encodeWholeExperimentalV3Checkpoint(&whole, state, profile); err != nil {
				t.Fatal(err)
			}
			writer := experimentalCheckpointWriteFunc(func(raw []byte) (int, error) {
				if test.count >= 64 && len(raw) > 16<<10 {
					t.Fatalf("large checkpoint wrote %d bytes at once", len(raw))
				}
				return candidate.Write(raw)
			})
			if err := state.encodeExperimentalV3Checkpoint(writer, profile); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(whole.Bytes(), candidate.Bytes()) {
				t.Fatal("version-4 checkpoint bytes changed")
			}
			if test.count != MaxRetainHeaders {
				return
			}
			// Fail after the first complete chunk. A late output error must
			// stop the writer and leave only the already accepted prefix.
			cause := errors.New("later checkpoint write")
			candidate.Reset()
			calls := 0
			fail := experimentalCheckpointWriteFunc(func(raw []byte) (int, error) {
				calls++
				if calls == 2 {
					return 0, cause
				}
				return candidate.Write(raw)
			})
			if err := state.WriteCheckpoint(fail); !errors.Is(err, cause) || calls != 2 || candidate.Len() != 16<<10 {
				t.Fatal("large checkpoint did not retain the first chunk and report the late error", calls, err)
			}
		})
	}
}

func BenchmarkExperimentalV3CheckpointWindowEncoding(b *testing.B) {
	state := checkpointEncodingFixture(b, MaxRetainHeaders)
	profile := state.data.config.profile
	profile.Source = experimentalV3ExportSource
	var expected bytes.Buffer
	if err := encodeWholeExperimentalV3Checkpoint(&expected, state, profile); err != nil {
		b.Fatal(err)
	}
	b.Run("whole", func(b *testing.B) {
		b.SetBytes(int64(expected.Len()))
		b.ReportAllocs()
		for b.Loop() {
			if err := encodeWholeExperimentalV3Checkpoint(io.Discard, state, profile); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("stream", func(b *testing.B) {
		b.SetBytes(int64(expected.Len()))
		b.ReportAllocs()
		for b.Loop() {
			if err := state.WriteCheckpoint(io.Discard); err != nil {
				b.Fatal(err)
			}
		}
	})
}
