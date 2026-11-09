// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"unicode/utf8"

	"github.com/0x3639/zenon-spv/internal/chain"
)

const experimentalV3StateFormat = "zenon-experimental-v3-owned-state/v1"

// Version 4 is refused by existing native v1/v2 state readers. The separate
// format string and exact schema prevent native files entering this path.
type experimentalV3File struct {
	Format  string                `json:"format"`
	Version uint32                `json:"version"`
	Context chain.Hash            `json:"context"`
	Profile ExperimentalV3Profile `json:"profile"`
	Policy  ExperimentalV3Policy  `json:"policy"`
	Headers experimentalV3Window  `json:"retained_headers"`
}

var ErrExperimentalV3StateFile = errors.New("invalid experimental v3 state file")

func (f *experimentalV3File) UnmarshalJSON(raw []byte) error {
	if f == nil || int64(len(raw)) > MaxExperimentalV3StateBytes || !utf8.Valid(raw) {
		return ErrExperimentalV3StateFile
	}
	var next experimentalV3File
	var text string
	if err := decodeRequiredObject(raw, map[string]any{
		"format": &next.Format, "version": &next.Version, "context": &text,
		"profile": &next.Profile, "policy": &next.Policy, "retained_headers": next.Headers.readValue,
	}); err != nil {
		return ErrExperimentalV3StateFile
	}
	if next.Format != experimentalV3StateFormat || next.Version != 4 || len(text) != 64 || next.Context.UnmarshalText([]byte(text)) != nil {
		return ErrExperimentalV3StateFile
	}
	canonical, _ := next.Context.MarshalText()
	if string(canonical) != text {
		return ErrExperimentalV3StateFile
	}
	*f = next
	return nil
}

type experimentalV3Window []chain.CandidateV3Header

func (w *experimentalV3Window) UnmarshalJSON(raw []byte) error {
	if w == nil || int64(len(raw)) > MaxExperimentalV3StateBytes {
		return ErrExperimentalV3StateFile
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var next experimentalV3Window
	if err := next.readValue(d); err != nil {
		return err
	}
	if d.Decode(new(json.RawMessage)) != io.EOF {
		return ErrExperimentalV3StateFile
	}
	*w = next
	return nil
}

// readValue leaves the enclosing object's remaining fields and EOF to its
// decoder. It buffers individual headers rather than the full retained array.
func (w *experimentalV3Window) readValue(d *json.Decoder) error {
	if token, err := d.Token(); err != nil || token != json.Delim('[') {
		return ErrExperimentalV3StateFile
	}
	rows := make(experimentalV3Window, 0)
	for d.More() {
		if len(rows) >= MaxRetainHeaders {
			return ErrExperimentalV3StateFile
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return ErrExperimentalV3StateFile
		}
		h, err := chain.DecodeCandidateV3Header(value)
		if err != nil {
			return ErrExperimentalV3StateFile
		}
		rows = append(rows, h)
	}
	if token, err := d.Token(); err != nil || token != json.Delim(']') {
		return ErrExperimentalV3StateFile
	}
	*w = rows
	return nil
}

// Save requires exclusive caller ownership across load/extend/save (for example
// internal/statelock). The native atomic writer supplies temp, bounded encoding,
// file sync, close, rename and non-Windows parent sync. Windows retains its
// documented weaker replacement/durability guarantee. A post-rename error may
// leave the new state visible. Signature verification is not repeated here.
func (s ExperimentalV3State) Save(path string) error {
	return s.saveExperimentalV3(path, os.Open)
}

func (s ExperimentalV3State) saveExperimentalV3(path string, openDir func(string) (*os.File, error)) error {
	if s.data == nil {
		return ErrUninitializedState
	}
	return writeAtomicStateFile(path, func(w io.Writer) error {
		return s.encodeExperimentalV3Checkpoint(w, s.data.config.profile)
	}, openDir)
}

// LoadTrustedExperimentalV3State requires a trusted regular local file plus
// independently selected settings and context pin. Every retained header's
// layout, root-bound hash, signature, producer authorization and links are
// rechecked before returning a handle. Missing files remain errors. Evicted
// ancestry and file authenticity cannot be reconstructed from the saved tail.
func LoadTrustedExperimentalV3State(path string, profile ExperimentalV3Profile, policy ExperimentalV3Policy, schedule *ProducerSchedule, expected chain.Hash) (ExperimentalV3State, error) {
	state, err := NewExperimentalV3State(profile, policy, schedule, expected)
	if err != nil {
		return ExperimentalV3State{}, err
	}
	f, info, err := openStateInput(path, openReadOnlyStateFile)
	if err != nil {
		return ExperimentalV3State{}, err
	}
	defer func() { _ = f.Close() }()
	if info.Size() > MaxExperimentalV3StateBytes {
		return ExperimentalV3State{}, ErrStateFileTooLarge
	}
	raw, err := readStateBytes(f, MaxExperimentalV3StateBytes, info.Size())
	if err != nil {
		return ExperimentalV3State{}, err
	}
	return decodeTrustedExperimentalV3State(raw, state)
}

func decodeTrustedExperimentalV3State(raw []byte, selected ExperimentalV3State) (ExperimentalV3State, error) {
	if selected.data == nil {
		return ExperimentalV3State{}, ErrUninitializedState
	}
	if int64(len(raw)) > MaxExperimentalV3StateBytes {
		return ExperimentalV3State{}, ErrStateFileTooLarge
	}
	var file experimentalV3File
	if json.Unmarshal(raw, &file) != nil {
		return ExperimentalV3State{}, ErrExperimentalV3StateFile
	}
	c := selected.data.config
	if file.Context != c.context.Fingerprint || file.Policy != c.policy {
		return ExperimentalV3State{}, ErrContextFingerprintMismatch
	}
	// Provenance labels do not select verification behavior or pin identity.
	file.Profile.Source = c.profile.Source
	if file.Profile != c.profile {
		return ExperimentalV3State{}, ErrContextFingerprintMismatch
	}
	if len(file.Headers) > int(c.policy.RetainHeaders) || (len(file.Headers) > 0 && uint64(len(file.Headers)) < c.policy.W) {
		return ExperimentalV3State{}, ErrExperimentalV3StateFile
	}
	for i, h := range file.Headers {
		if r := validateExperimentalV3Header(h, c, i); r.Outcome != OutcomeAccept {
			return ExperimentalV3State{}, ErrExperimentalV3StateFile
		}
		if i == 0 {
			if h.Header.Height-c.profile.Anchor.Height == 1 && h.Header.PreviousHash != c.profile.Anchor.HeaderHash {
				return ExperimentalV3State{}, ErrExperimentalV3StateFile
			}
		} else {
			previous := file.Headers[i-1].Header
			if h.Header.Height <= previous.Height || h.Header.Height-previous.Height != 1 || h.Header.PreviousHash != previous.HeaderHash {
				return ExperimentalV3State{}, ErrExperimentalV3StateFile
			}
		}
	}
	// Only freshly decoded arrays enter this private state; no caller-owned tail
	// or diagnostic context can be supplied as authority.
	return ExperimentalV3State{data: &experimentalV3StateData{config: c, headers: file.Headers, trustedLocal: len(file.Headers) > 0}}, nil
}
