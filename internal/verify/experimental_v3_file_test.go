// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func experimentalV3Saved(t *testing.T, f experimentalV3Fixture) (ExperimentalV3State, string, []byte) {
	t.Helper()
	s := experimentalV3New(t, f)
	r, s := s.Extend(f.headers)
	if r.Outcome != OutcomeAccept {
		t.Fatal(r)
	}
	path := filepath.Join(t.TempDir(), "experimental-state.json")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return s, path, raw
}

func TestExperimentalV3TrustedPersistence(t *testing.T) {
	f := experimentalV3Inputs(t)
	s := experimentalV3New(t, f)
	path := filepath.Join(t.TempDir(), "experimental-state.json")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	empty, err := LoadTrustedExperimentalV3State(path, f.profile, f.policy, f.schedule, f.pin)
	if err != nil || !empty.Empty() {
		t.Fatal("empty persistence", err)
	}
	r, prefix := s.Extend(f.headers[:2])
	if r.Outcome != OutcomeAccept {
		t.Fatal(r)
	}
	if err := prefix.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTrustedExperimentalV3State(path, f.profile, f.policy, f.schedule, f.pin)
	if err != nil {
		t.Fatal(err)
	}
	if root, err := loaded.RootAt(12, f.headers[0].Header.HeaderHash, f.pin); err != nil || root != f.headers[0].StateRoot {
		t.Fatal("resumed root mismatch", err)
	}
	r, tail := loaded.Extend(f.headers[2:])
	if r.Outcome != OutcomeAccept {
		t.Fatal(r)
	}
	trusted := false
	for _, v := range r.TrustAssumptions {
		if v == TrustPersistedState {
			trusted = true
		}
	}
	if !trusted {
		t.Fatal("trusted local provenance omitted")
	}
	if err := tail.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHeaderState(path); err == nil {
		t.Fatal("native state loader accepted experimental schema")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary persistence files remain", err)
	}
	if _, err := LoadTrustedExperimentalV3State(path+"-missing", f.profile, f.policy, f.schedule, f.pin); !os.IsNotExist(err) {
		t.Fatal("missing state initialized silently", err)
	}
	if _, err := LoadTrustedExperimentalV3State(filepath.Dir(path), f.profile, f.policy, f.schedule, f.pin); !errors.Is(err, ErrStateFileNotRegular) {
		t.Fatal("directory accepted as state", err)
	}
	var zero ExperimentalV3State
	if err := zero.Save(path); err != ErrUninitializedState {
		t.Fatal("zero handle persisted", err)
	}
}

func TestExperimentalV3PersistenceRejectsChangedSettings(t *testing.T) {
	f := experimentalV3Inputs(t)
	_, path, _ := experimentalV3Saved(t, f)
	for _, name := range []string{"genesis", "anchor", "profile", "policy", "schedule"} {
		t.Run(name, func(t *testing.T) {
			changed := experimentalV3Inputs(t)
			switch name {
			case "genesis":
				changed.profile.Genesis.HeaderHash[0] ^= 1
			case "anchor":
				changed.profile.Anchor.HeaderHash[0] ^= 1
			case "profile":
				changed.profile.ValidThrough = 15
			case "policy":
				changed.policy.RetainHeaders = 3
			case "schedule":
				entries := append([]ProducerEntry(nil), changed.schedule.Entries...)
				entries[0].ProducingAddr[0] ^= 1
				changed.schedule, _ = NewProducerSchedule(100, changed.schedule.Coverage, entries, nil, nil)
			}
			c, err := ExperimentalV3ContextFor(changed.profile, changed.policy, changed.schedule)
			if err != nil {
				t.Fatal(err)
			}
			state, err := LoadTrustedExperimentalV3State(path, changed.profile, changed.policy, changed.schedule, c.Fingerprint)
			if err != ErrContextFingerprintMismatch || state.data != nil {
				t.Fatal("state migrated to a different context", err)
			}
		})
	}
	// An index supplied by the caller is never authority: a fresh validated copy
	// is used, while a changed substantive schedule hash cannot retain the pin.
	f.schedule.idx = map[uint64]int{13: 0}
	loaded, err := LoadTrustedExperimentalV3State(path, f.profile, f.policy, f.schedule, f.pin)
	if err != nil || loaded.Empty() {
		t.Fatal("caller index was not rebuilt", err)
	}
}

func TestExperimentalV3PersistenceRejectsCorruption(t *testing.T) {
	f := experimentalV3Inputs(t)
	_, path, raw := experimentalV3Saved(t, f)
	cases := map[string]func(map[string]json.RawMessage){
		"format":  func(v map[string]json.RawMessage) { v["format"] = json.RawMessage(`"other"`) },
		"version": func(v map[string]json.RawMessage) { v["version"] = json.RawMessage(`3`) },
		"context": func(v map[string]json.RawMessage) { v["context"] = experimentalV3JSON(t, strings.Repeat("0", 64)) },
		"policy": func(v map[string]json.RawMessage) {
			v["policy"] = json.RawMessage(`{"w":1,"retain_headers":3,"max_batch_headers":3}`)
		},
		"null-window":      func(v map[string]json.RawMessage) { v["retained_headers"] = json.RawMessage(`null`) },
		"oversized-window": func(v map[string]json.RawMessage) { v["retained_headers"] = experimentalV3JSON(t, f.headers) },
		"unknown":          func(v map[string]json.RawMessage) { v["private-configuration-marker"] = json.RawMessage(`true`) },
	}
	for _, kind := range []string{"root", "rehashed-root", "signature", "key", "reverse", "duplicate", "unknown-header-field"} {
		cases[kind] = func(v map[string]json.RawMessage) {
			var headers []json.RawMessage
			if json.Unmarshal(v["retained_headers"], &headers) != nil {
				t.Fatal("fixture window")
			}
			fields := experimentalV3Fields(t, headers[0])
			switch kind {
			case "root":
				fields["stateRoot"] = experimentalV3JSON(t, strings.Repeat("0", 64))
			case "rehashed-root":
				h := f.headers[1]
				h.StateRoot[0] ^= 1
				h.Header.HeaderHash, _ = h.ComputeHash()
				fields = experimentalV3Fields(t, experimentalV3JSON(t, h))
			case "signature":
				fields["signature"] = experimentalV3JSON(t, base64.StdEncoding.EncodeToString(make([]byte, 64)))
			case "key":
				fields["publicKey"] = experimentalV3JSON(t, base64.StdEncoding.EncodeToString(make([]byte, 32)))
			case "reverse":
				headers[0], headers[1] = headers[1], headers[0]
			case "duplicate":
				headers[1] = headers[0]
			case "unknown-header-field":
				fields["private-configuration-marker"] = json.RawMessage(`true`)
			}
			if kind != "reverse" && kind != "duplicate" {
				headers[0] = experimentalV3JSON(t, fields)
			}
			v["retained_headers"] = experimentalV3JSON(t, headers)
		}
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			fields := experimentalV3Fields(t, raw)
			change(fields)
			bad := experimentalV3JSON(t, fields)
			if err := os.WriteFile(path, bad, 0600); err != nil {
				t.Fatal(err)
			}
			state, err := LoadTrustedExperimentalV3State(path, f.profile, f.policy, f.schedule, f.pin)
			if err == nil || state.data != nil {
				t.Fatal("corrupt retained state supplied authority")
			}
		})
	}
	for name := range experimentalV3Fields(t, raw) {
		for _, kind := range []string{"missing", "null", "duplicate"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				fields := experimentalV3Fields(t, raw)
				switch kind {
				case "missing":
					delete(fields, name)
				case "null":
					fields[name] = json.RawMessage(`null`)
				}
				bad := experimentalV3JSON(t, fields)
				if kind == "duplicate" {
					bad = append(bad[:len(bad)-1], ',')
					bad = append(bad, experimentalV3JSON(t, name)...)
					bad = append(bad, ':')
					bad = append(bad, fields[name]...)
					bad = append(bad, '}')
				}
				if state, err := decodeTrustedExperimentalV3State(bad, experimentalV3New(t, f)); err == nil || state.data != nil {
					t.Fatal("ambiguous state schema accepted")
				}
			})
		}
	}
	if state, err := decodeTrustedExperimentalV3State(append(raw, []byte("{}")...), experimentalV3New(t, f)); err == nil || state.data != nil {
		t.Fatal("trailing state document accepted")
	}
	invalidUTF8 := bytes.Replace(raw, []byte(f.profile.Source), []byte{255}, 1)
	if state, err := decodeTrustedExperimentalV3State(invalidUTF8, experimentalV3New(t, f)); err == nil || state.data != nil {
		t.Fatal("invalid UTF-8 state accepted")
	}
	fields := experimentalV3Fields(t, raw)
	p := f.profile
	p.Source = "another provenance label"
	fields["profile"] = experimentalV3JSON(t, p)
	if state, err := decodeTrustedExperimentalV3State(experimentalV3JSON(t, fields), experimentalV3New(t, f)); err != nil || state.Empty() {
		t.Fatal("metadata-only label changed substantive context", err)
	}
}

func TestExperimentalV3PersistenceBoundsAndFailureAtomicity(t *testing.T) {
	f := experimentalV3Inputs(t)
	s, path, raw := experimentalV3Saved(t, f)
	pad := append(bytes.Repeat([]byte{' '}, int(MaxExperimentalV3StateBytes)-len(raw)), raw...)
	if err := os.WriteFile(path, pad, 0600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadTrustedExperimentalV3State(path, f.profile, f.policy, f.schedule, f.pin); err != nil || loaded.Empty() {
		t.Fatal("exact state byte limit", err)
	}
	if err := os.WriteFile(path, append(pad, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if state, err := LoadTrustedExperimentalV3State(path, f.profile, f.policy, f.schedule, f.pin); err != ErrStateFileTooLarge || state.data != nil {
		t.Fatal("oversized state accepted", err)
	}
	member := experimentalV3JSON(t, f.headers[0])
	rows := make([]json.RawMessage, MaxRetainHeaders+1)
	for i := range rows {
		rows[i] = member
	}
	before := experimentalV3Window{f.headers[0]}
	target := before
	if json.Unmarshal(experimentalV3JSON(t, rows), &target) == nil || !reflect.DeepEqual(target, before) {
		t.Fatal("window member bound failed or published a prefix")
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("controlled encoding failure")
	err = writeAtomicStateFile(path, func(w io.Writer) error {
		if _, err := w.Write([]byte("partial")); err != nil {
			return err
		}
		return cause
	}, os.Open)
	if !errors.Is(err, cause) {
		t.Fatal("encoding failure erased", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(old, after) {
		t.Fatal("failed encoding replaced the prior state", err)
	}
	called := false
	err = s.saveExperimentalV3(path, func(string) (*os.File, error) { called = true; return nil, cause })
	if runtime.GOOS == "windows" {
		if err != nil || called {
			t.Fatal("Windows parent-sync contract changed", err)
		}
	} else if !errors.Is(err, cause) || !called {
		t.Fatal("post-rename directory error hidden", err)
	}
	if loaded, err := LoadTrustedExperimentalV3State(path, f.profile, f.policy, f.schedule, f.pin); err != nil || loaded.Empty() {
		t.Fatal("visible post-rename state lost integrity", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("owned atomic-writer temporary file remains", err)
	}
}

func TestExperimentalV3NativeWriterByteCompatibility(t *testing.T) {
	f := experimentalV3Inputs(t)
	profile := &ProtocolProfile{Version: 1, Anchor: f.profile.Genesis, ValidThrough: 11, V2FromHeight: 11, Source: "recorded-public-header-fixture"}
	s, err := NewVerifiedState(f.profile.Genesis, VerifyOptions{Policy: Policy{W: 1, RetainHeaders: 2, MaxHeaders: 16, ProtocolProfile: profile}})
	if err != nil {
		t.Fatal(err)
	}
	r, s := s.Extend(f.legacy)
	if r.Outcome != OutcomeAccept {
		t.Fatal(r)
	}
	path := filepath.Join(t.TempDir(), "native-state.json")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	// Independent Python framing of the old persisted schema, public H10/H11,
	// exact field order, two-space indentation and trailing newline.
	if len(raw) != 2073 || hex.EncodeToString(sum[:]) != "b953f6794b1995cdd70f7836904e5b363a88e70555e1e1176210333d2aaa746f" {
		t.Fatal("native persisted bytes changed")
	}
	if _, err := LoadHeaderState(path); err != nil {
		t.Fatal("native round trip", err)
	}
	if got, err := LoadTrustedExperimentalV3State(path, f.profile, f.policy, f.schedule, f.pin); err == nil || got.data != nil {
		t.Fatal("experimental loader accepted a native file")
	}
	if chain.ValidateHeaderVersion(3) == nil {
		t.Fatal("production version gate changed")
	}
}
