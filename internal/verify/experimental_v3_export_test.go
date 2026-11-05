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
