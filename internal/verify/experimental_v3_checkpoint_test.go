// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"testing/iotest"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func batchCheckpointBytes(t *testing.T, f batchContextFixture) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := f.state.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestExperimentalV3PinnedCheckpointQuery(t *testing.T) {
	f := newBatchContextFixture(t)
	raw := batchCheckpointBytes(t, f)
	digest := sha256.Sum256(raw)
	state, err := DecodePinnedTrustedExperimentalV3State(raw, f.Config.HeaderProfile, f.Config.HeaderPolicy, f.Config.Schedule, f.state.data.config.context.Fingerprint, digest)
	if err != nil || state.Empty() || !state.data.trustedLocal || len(state.data.headers) != 2 {
		t.Fatal("trusted retained checkpoint", err)
	}
	streamed, size, err := f.state.ReadPinnedTrustedCheckpoint(iotest.OneByteReader(bytes.NewReader(raw)), digest)
	if err != nil || size != int64(len(raw)) || !reflect.DeepEqual(streamed, state) {
		t.Fatal("streamed checkpoint changed the retained state or byte count", err)
	}
	state = streamed
	// The saved tail omits H87/H88. It rechecks only retained H89/H90;
	// trusted local ancestry remains explicit rather than reconstructed.
	if _, ok := state.HeaderAtHeight(88); ok {
		t.Fatal("evicted ancestry manufactured")
	}
	clear(raw)
	q, err := NewExperimentalBatchContextQuery(state, f.Config.QueryProfile, f.Request.Context)
	if err != nil {
		t.Fatal(err)
	}
	got, err := q.QueryWitnesses(f.Request, f.witness)
	if err != nil {
		t.Fatal(err)
	}
	want, err := f.query.QueryWitnesses(f.Request, f.witness)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, trust := range got.HeaderTrust {
		found = found || trust == TrustPersistedState
	}
	if !found {
		t.Fatal("checkpoint trust assumption omitted")
	}
	got.HeaderTrust = want.HeaderTrust
	if !reflect.DeepEqual(got, want) {
		t.Fatal("checkpoint query changed typed membership")
	}
}

func TestExperimentalV3CheckpointReusesPreparedSelection(t *testing.T) {
	f := newBatchContextFixture(t)
	raw := batchCheckpointBytes(t, f)
	pin := f.state.data.config.context.Fingerprint
	settings, err := PrepareExperimentalV3Configuration(f.Config.HeaderProfile, f.Config.HeaderPolicy, f.Config.Schedule)
	if err != nil || settings.Context() != f.state.data.config.context {
		t.Fatal("prepared context differs from the original selection", err)
	}
	badPin := pin
	badPin[0] ^= 1
	for _, refused := range []chain.Hash{{}, badPin} {
		if state, err := settings.NewState(refused); !errors.Is(err, ErrContextFingerprintMismatch) || state.data != nil {
			t.Fatal("prepared settings accepted an unselected context", err)
		}
	}
	if state, err := (ExperimentalV3Configuration{}).NewState(pin); !errors.Is(err, ErrContextFingerprintMismatch) || state.data != nil {
		t.Fatal("unprepared settings created a state", err)
	}

	// Changes after preparation must not affect a later state or its resume.
	f.Config.Schedule.Entries[0].TimestampUnix++
	f.Config.Schedule.Coverage[0].ThroughHeight--
	selected, err := settings.NewState(pin)
	if err != nil || !selected.Empty() {
		t.Fatal("prepared selection did not start empty", err)
	}
	digest := sha256.Sum256(raw)
	resumed, err := selected.DecodePinnedTrustedCheckpoint(raw, digest)
	if err != nil || resumed.data == nil || !resumed.data.trustedLocal || !selected.Empty() ||
		resumed.data.config.schedule != selected.data.config.schedule ||
		!reflect.DeepEqual(resumed.data.headers, f.state.data.headers) {
		t.Fatal("resume failed to reuse the selected settings and recheck the retained tail", err)
	}
	digest[0] ^= 1
	if state, err := selected.DecodePinnedTrustedCheckpoint(raw, digest); !errors.Is(err, ErrExperimentalV3CheckpointDigest) || state.data != nil {
		t.Fatal("prepared resume accepted a different digest", err)
	}

	var file experimentalV3File
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	file.Headers[0].Header.Signature[0] ^= 1
	raw = experimentalV3JSON(t, file)
	if state, err := selected.DecodePinnedTrustedCheckpoint(raw, sha256.Sum256(raw)); !errors.Is(err, ErrExperimentalV3StateFile) || state.data != nil {
		t.Fatal("prepared resume accepted a corrupt retained signature", err)
	}
}

func TestExperimentalV3PinnedCheckpointFailures(t *testing.T) {
	f := newBatchContextFixture(t)
	raw := batchCheckpointBytes(t, f)
	for _, name := range []string{"zero-digest", "wrong-digest", "different-bytes", "oversized", "context-pin", "zero-context", "file-context", "policy", "profile", "unknown-field", "duplicate-field", "trailing-json", "null-headers", "signature", "root", "linkage", "native-format"} {
		t.Run(name, func(t *testing.T) {
			value := bytes.Clone(raw)
			pin := f.state.data.config.context.Fingerprint
			digest := sha256.Sum256(value)
			want := ErrExperimentalV3StateFile
			switch name {
			case "zero-digest":
				digest, want = [sha256.Size]byte{}, ErrExperimentalV3CheckpointDigest
			case "wrong-digest":
				digest[0] ^= 1
				want = ErrExperimentalV3CheckpointDigest
			case "different-bytes":
				value = append(value, ' ')
				want = ErrExperimentalV3CheckpointDigest
			case "oversized":
				value = bytes.Repeat([]byte{' '}, int(MaxExperimentalV3StateBytes)+1)
				want = ErrStateFileTooLarge
			case "context-pin", "zero-context":
				pin[0] ^= 1
				if name == "zero-context" {
					pin = chain.Hash{}
				}
				want = ErrContextFingerprintMismatch
			default:
				var file experimentalV3File
				if json.Unmarshal(value, &file) != nil {
					t.Fatal("checkpoint fixture")
				}
				switch name {
				case "file-context":
					file.Context[0] ^= 1
					want = ErrContextFingerprintMismatch
				case "policy":
					file.Policy.RetainHeaders++
					want = ErrContextFingerprintMismatch
				case "profile":
					file.Profile.ValidThrough++
					want = ErrContextFingerprintMismatch
				case "signature":
					file.Headers[0].Header.Signature[0] ^= 1
				case "native-format":
					file.Version = 3
				}
				var err error
				value, err = json.Marshal(file)
				if err != nil {
					t.Fatal(err)
				}
				switch name {
				case "unknown-field":
					value = append(value[:len(value)-1], []byte(`,"provider_root":"ignored"}`)...)
				case "duplicate-field":
					value = append(value[:len(value)-1], []byte(`,"version":4}`)...)
				case "trailing-json":
					value = append(value, []byte(`{}`)...)
				case "null-headers", "root", "linkage":
					var fields map[string]json.RawMessage
					if json.Unmarshal(value, &fields) != nil {
						t.Fatal("checkpoint fields")
					}
					if name == "null-headers" {
						fields["retained_headers"] = json.RawMessage("null")
					} else {
						// The typed header marshaler correctly refuses a changed
						// hash projection. Corrupt the serialized input instead
						// so the checkpoint decoder itself receives the control.
						var rows []map[string]json.RawMessage
						if json.Unmarshal(fields["retained_headers"], &rows) != nil || len(rows) != 2 {
							t.Fatal("retained header fixture")
						}
						if name == "root" {
							rows[0]["stateRoot"] = json.RawMessage(`"1111111111111111111111111111111111111111111111111111111111111111"`)
						} else {
							rows[1]["previousHash"] = json.RawMessage(`"1111111111111111111111111111111111111111111111111111111111111111"`)
						}
						fields["retained_headers"], err = json.Marshal(rows)
						if err != nil {
							t.Fatal(err)
						}
					}
					value, err = json.Marshal(fields)
					if err != nil {
						t.Fatal(err)
					}
				}
				// Matching byte identity is insufficient: every strict state,
				// context, signature and linkage check must still execute.
				digest = sha256.Sum256(value)
			}
			state, err := DecodePinnedTrustedExperimentalV3State(value, f.Config.HeaderProfile, f.Config.HeaderPolicy, f.Config.Schedule, pin, digest)
			if !errors.Is(err, want) || state.data != nil {
				t.Fatal("invalid checkpoint supplied authority", err, want)
			}
			if pin == f.state.data.config.context.Fingerprint {
				state, size, err := f.state.ReadPinnedTrustedCheckpoint(bytes.NewReader(value), digest)
				if !errors.Is(err, want) || state.data != nil || size != 0 {
					t.Fatal("streamed checkpoint changed the refusal", err, want)
				}
			}
		})
	}
}

func TestExperimentalV3PinnedCheckpointStreamInput(t *testing.T) {
	f := newBatchContextFixture(t)
	var file experimentalV3File
	if err := json.Unmarshal(batchCheckpointBytes(t, f), &file); err != nil {
		t.Fatal(err)
	}
	// Source is a provenance label. Include both a split multibyte rune and a
	// literal replacement character that must not be mistaken for bad UTF-8.
	file.Profile.Source = "checkpoint \U0001f310 \ufffd"
	raw := experimentalV3JSON(t, file)
	state, size, err := f.state.ReadPinnedTrustedCheckpoint(iotest.OneByteReader(bytes.NewReader(raw)), sha256.Sum256(raw))
	if err != nil || size != int64(len(raw)) || !reflect.DeepEqual(state.data.headers, f.state.data.headers) {
		t.Fatal("split UTF-8 checkpoint did not preserve retained evidence", err)
	}
	badUTF8 := bytes.Replace(raw, []byte(file.Profile.Source), []byte{0xff}, 1)
	for _, tc := range []struct {
		raw  []byte
		pin  [sha256.Size]byte
		want error
	}{
		{badUTF8, sha256.Sum256(badUTF8), ErrExperimentalV3StateFile},
		{badUTF8, sha256.Sum256(raw), ErrExperimentalV3CheckpointDigest},
		{append(bytes.Clone(raw), ' '), sha256.Sum256(raw), ErrExperimentalV3CheckpointDigest},
	} {
		if state, size, err := f.state.ReadPinnedTrustedCheckpoint(bytes.NewReader(tc.raw), tc.pin); !errors.Is(err, tc.want) || state.data != nil || size != 0 {
			t.Fatal("checkpoint input or digest refusal changed", err, tc.want)
		}
	}
	cause := errors.New("controlled checkpoint read error")
	input := stateReadFailure{bytes.NewReader(raw), cause}
	if state, size, err := f.state.ReadPinnedTrustedCheckpoint(input, sha256.Sum256(raw)); !errors.Is(err, ErrExperimentalV3CheckpointInput) ||
		!errors.Is(err, cause) || state.data != nil || size != 0 {
		t.Fatal("complete JSON hid a checkpoint read error", err)
	}
}

func BenchmarkExperimentalV3PinnedCheckpointInput(b *testing.B) {
	f := experimentalV3RetentionInputs(b, MaxRetainHeaders, MaxRetainHeaders)
	state := experimentalV3New(b, f)
	headers := make(experimentalV3Window, MaxRetainHeaders)
	for i := range headers {
		headers[i] = f.headers[i%len(f.headers)]
	}
	raw, err := json.Marshal(experimentalV3File{Format: experimentalV3StateFormat, Version: 4, Context: f.pin,
		Profile: f.profile, Policy: f.policy, Headers: headers})
	if err != nil {
		b.Fatal(err)
	}
	pin := sha256.Sum256(raw)
	// These are repeated recorded envelopes. Both paths decode all of them
	// and check the digest before rejecting their non-contiguous history.
	b.Run("buffered", func(b *testing.B) {
		b.SetBytes(int64(len(raw)))
		b.ReportAllocs()
		for b.Loop() {
			copied, err := readStateBytes(bytes.NewReader(raw), MaxExperimentalV3StateBytes, int64(len(raw)))
			if err != nil {
				b.Fatal(err)
			}
			if loaded, err := state.DecodePinnedTrustedCheckpoint(copied, pin); !errors.Is(err, ErrExperimentalV3StateFile) || loaded.data != nil {
				b.Fatal("unexpected buffered checkpoint outcome", err)
			}
		}
	})
	b.Run("streamed", func(b *testing.B) {
		b.SetBytes(int64(len(raw)))
		b.ReportAllocs()
		for b.Loop() {
			if loaded, size, err := state.ReadPinnedTrustedCheckpoint(bytes.NewReader(raw), pin); !errors.Is(err, ErrExperimentalV3StateFile) ||
				loaded.data != nil || size != 0 {
				b.Fatal("unexpected streamed checkpoint outcome", err)
			}
		}
	})
}
