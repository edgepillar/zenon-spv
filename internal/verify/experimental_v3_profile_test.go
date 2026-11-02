// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

type experimentalV3Fixture struct {
	profile  ExperimentalV3Profile
	policy   ExperimentalV3Policy
	schedule *ProducerSchedule
	headers  []chain.CandidateV3Header
	legacy   []chain.Header
	pin      chain.Hash
}

// This reuses public signatures. It never signs, starts a node or treats the
// isolated chain-100 cohort as the selected source's chain-69 live network.
func experimentalV3Inputs(t *testing.T) experimentalV3Fixture {
	t.Helper()
	raw, err := os.ReadFile("../testdata/conformance/first-v3-node-headers.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if len(raw) != 21634 || hex.EncodeToString(sum[:]) != "78222ac4bba092fc9f4b6775d158a8e5d013c22b7e7a85948dce6453f26cff12" {
		t.Fatal("public node fixture changed")
	}
	var captured struct {
		Trace struct {
			ChainID uint64     `json:"chain_id"`
			Genesis chain.Hash `json:"genesis_hash"`
			Rows    []struct {
				Height  uint64          `json:"height"`
				Version uint64          `json:"version"`
				Hash    chain.Hash      `json:"hash"`
				Header  json.RawMessage `json:"header"`
			} `json:"rows"`
		} `json:"trace"`
	}
	if json.Unmarshal(raw, &captured) != nil || captured.Trace.ChainID != 100 {
		t.Fatal("unexpected source cohort")
	}
	f := experimentalV3Fixture{profile: ExperimentalV3Profile{Version: 1, Genesis: GenesisTrustRoot{ChainID: 100, Height: 1, HeaderHash: captured.Trace.Genesis}, FirstV3Height: 12, ValidThrough: 14, NodeRevision: ExperimentalV3NodeRevision, Source: "isolated public node fixture, not network activation"}, policy: ExperimentalV3Policy{W: 1, RetainHeaders: 2, MaxBatchHeaders: 3}}
	entries := []ProducerEntry{}
	for _, row := range captured.Trace.Rows {
		if row.Height == 11 {
			f.profile.Anchor = GenesisTrustRoot{ChainID: 100, Height: 11, HeaderHash: row.Hash}
		}
		if row.Height > 1 && row.Version < 3 {
			var h chain.Header
			if json.Unmarshal(row.Header, &h) != nil {
				t.Fatal("legacy fixture decode")
			}
			f.legacy = append(f.legacy, h)
		}
		if row.Version == 3 {
			h, err := chain.DecodeCandidateV3Header(row.Header)
			if err != nil {
				t.Fatal(err)
			}
			f.headers = append(f.headers, h)
			entries = append(entries, ProducerEntry{Height: h.Header.Height, TimestampUnix: h.Header.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.Header.PublicKey)})
		}
	}
	if len(f.headers) != 3 || len(f.legacy) != 10 {
		t.Fatal("missing recorded signatures")
	}
	f.schedule, err = NewProducerSchedule(100, []ProducerCoverage{{FromHeight: 12, ThroughHeight: 14}}, entries, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ExperimentalV3ContextFor(f.profile, f.policy, f.schedule)
	if err != nil {
		t.Fatal(err)
	}
	f.pin = c.Fingerprint
	return f
}

func experimentalV3New(t *testing.T, f experimentalV3Fixture) ExperimentalV3State {
	t.Helper()
	s, err := NewExperimentalV3State(f.profile, f.policy, f.schedule, f.pin)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func experimentalV3JSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func experimentalV3Fields(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("object fixture decode")
	}
	return fields
}

func TestExperimentalV3ContextIndependentGolden(t *testing.T) {
	f := experimentalV3Inputs(t)
	// Independent Python: canonical schedule preimage 148 bytes, context 243
	// bytes, uint64BE framing, raw genesis/anchor hashes and node revision bytes.
	if got, _ := f.schedule.ScheduleHash.MarshalText(); string(got) != "1101fc4fb75c9dbcfd26bc4ff7ec5b37b79522c130a18966d49bcc78ef6249ed" {
		t.Fatal("independent schedule hash mismatch")
	}
	if got, _ := f.pin.MarshalText(); string(got) != "1f6961594b3e8950a1dad80f0a1e26b491e743e0a8f527e91802698b5084bdd2" {
		t.Fatal("independent context hash mismatch")
	}
	f.profile.Source = "private-configuration-marker"
	f.schedule.SourcePeers = []string{"private-configuration-marker"}
	f.schedule.GeneratedAt = 123
	f.schedule.SourceHeights = map[string]uint64{"private-configuration-marker": 14}
	c, err := ExperimentalV3ContextFor(f.profile, f.policy, f.schedule)
	if err != nil || c.Fingerprint != f.pin || bytes.Contains(experimentalV3JSON(t, c), []byte("private-configuration-marker")) {
		t.Fatal("metadata must not enter diagnostics or behavior identity", err)
	}
	s := experimentalV3New(t, f)
	f.profile.Anchor.HeaderHash[0] ^= 1
	f.policy.W = 2
	f.schedule.Entries[0].ProducingAddr[0] ^= 1
	c.Policy.W = 99
	c.Fingerprint[0] ^= 1
	r, next := s.Extend(f.headers)
	if r.Outcome != OutcomeAccept {
		t.Fatal("captured settings changed through an alias", r)
	}
	own, err := next.Context()
	if err != nil || own.Fingerprint != f.pin || own.Policy.W != 1 {
		t.Fatal("owned context changed", err)
	}
	if next.RequireContextFingerprint(c.Fingerprint) != ErrContextFingerprintMismatch || next.RequireContextFingerprint(chain.Hash{}) != ErrContextFingerprintMismatch {
		t.Fatal("context mismatch accepted")
	}
}

func TestExperimentalV3ProfileAndPolicyRequiredFields(t *testing.T) {
	f := experimentalV3Inputs(t)
	for _, kind := range []string{"profile", "policy"} {
		var raw []byte
		if kind == "profile" {
			raw = experimentalV3JSON(t, f.profile)
		} else {
			raw = experimentalV3JSON(t, f.policy)
		}
		for name := range experimentalV3Fields(t, raw) {
			for _, change := range []string{"missing", "null", "duplicate", "case-alias"} {
				t.Run(kind+"/"+name+"/"+change, func(t *testing.T) {
					fields := experimentalV3Fields(t, raw)
					switch change {
					case "missing":
						delete(fields, name)
					case "null":
						fields[name] = json.RawMessage("null")
					case "case-alias":
						fields[strings.ToUpper(name)] = fields[name]
						delete(fields, name)
					}
					bad := experimentalV3JSON(t, fields)
					if change == "duplicate" {
						bad = append(bad[:len(bad)-1], ',')
						bad = append(bad, experimentalV3JSON(t, name)...)
						bad = append(bad, ':')
						bad = append(bad, fields[name]...)
						bad = append(bad, '}')
					}
					if kind == "profile" {
						target := f.profile
						before := target
						if json.Unmarshal(bad, &target) == nil || target != before {
							t.Fatal("profile error was not atomic")
						}
					} else {
						target := f.policy
						before := target
						if json.Unmarshal(bad, &target) == nil || target != before {
							t.Fatal("policy error was not atomic")
						}
					}
				})
			}
		}
	}
	for _, key := range []string{"genesis", "anchor"} {
		for _, field := range []string{"chain_id", "height", "header_hash"} {
			t.Run(key+"/"+field, func(t *testing.T) {
				fields := experimentalV3Fields(t, experimentalV3JSON(t, f.profile))
				nested := experimentalV3Fields(t, fields[key])
				delete(nested, field)
				fields[key] = experimentalV3JSON(t, nested)
				if _, err := DecodeExperimentalV3Profile(experimentalV3JSON(t, fields)); err != ErrExperimentalV3Profile {
					t.Fatal("nested anchor field omission accepted")
				}
			})
		}
		for _, kind := range []string{"prefixed-hash", "uppercase-hash", "short-hash"} {
			t.Run(key+"/"+kind, func(t *testing.T) {
				fields := experimentalV3Fields(t, experimentalV3JSON(t, f.profile))
				nested := experimentalV3Fields(t, fields[key])
				var hash string
				if json.Unmarshal(nested["header_hash"], &hash) != nil {
					t.Fatal("fixture hash")
				}
				switch kind {
				case "prefixed-hash":
					hash = "0x" + hash
				case "uppercase-hash":
					hash = strings.ToUpper(hash)
				case "short-hash":
					hash = hash[:62]
				}
				nested["header_hash"] = experimentalV3JSON(t, hash)
				fields[key] = experimentalV3JSON(t, nested)
				if _, err := DecodeExperimentalV3Profile(experimentalV3JSON(t, fields)); err != ErrExperimentalV3Profile {
					t.Fatal("noncanonical anchor hash accepted", err)
				}
			})
		}
	}
	raw := experimentalV3JSON(t, f.profile)
	invalidUTF8 := bytes.Replace(raw, []byte(f.profile.Source), []byte{255}, 1)
	if p, err := DecodeExperimentalV3Profile(invalidUTF8); err != ErrExperimentalV3Profile || p != (ExperimentalV3Profile{}) {
		t.Fatal("invalid UTF-8 profile accepted", err)
	}
	padded := append(bytes.Repeat([]byte{' '}, MaxExperimentalV3ProfileBytes-len(raw)), raw...)
	if p, err := DecodeExperimentalV3Profile(padded); err != nil || p != f.profile {
		t.Fatal("exact profile byte limit", err)
	}
	for _, bad := range [][]byte{append(padded, ' '), append(append([]byte(nil), raw...), []byte("{}")...), []byte("null"), []byte("[]")} {
		if p, err := DecodeExperimentalV3Profile(bad); err != ErrExperimentalV3Profile || p != (ExperimentalV3Profile{}) {
			t.Fatal("invalid profile returned a value", err)
		}
	}
}

func TestExperimentalV3ProfileSelectionBounds(t *testing.T) {
	f := experimentalV3Inputs(t)
	changes := map[string]func(*ExperimentalV3Profile){
		"version-zero": func(p *ExperimentalV3Profile) { p.Version = 0 }, "unknown-version": func(p *ExperimentalV3Profile) { p.Version = 2 },
		"unknown-source-revision": func(p *ExperimentalV3Profile) { p.NodeRevision = strings.Repeat("0", 40) },
		"genesis-height":          func(p *ExperimentalV3Profile) { p.Genesis.Height = 2 }, "zero-genesis": func(p *ExperimentalV3Profile) { p.Genesis.HeaderHash = chain.Hash{} },
		"mainnet": func(p *ExperimentalV3Profile) { p.Genesis.ChainID = 1; p.Anchor.ChainID = 1 }, "chain-mismatch": func(p *ExperimentalV3Profile) { p.Anchor.ChainID = 69 },
		"zero-anchor": func(p *ExperimentalV3Profile) { p.Anchor.HeaderHash = chain.Hash{} }, "first-v3-genesis": func(p *ExperimentalV3Profile) { p.FirstV3Height = 1 },
		"zero-activation": func(p *ExperimentalV3Profile) { p.FirstV3Height = 0 }, "anchor-before-boundary": func(p *ExperimentalV3Profile) { p.FirstV3Height = 13 },
		"empty-coverage": func(p *ExperimentalV3Profile) { p.ValidThrough = p.Anchor.Height },
		"empty-source":   func(p *ExperimentalV3Profile) { p.Source = " " }, "oversized-source": func(p *ExperimentalV3Profile) { p.Source = strings.Repeat("x", 1025) },
		"control-source": func(p *ExperimentalV3Profile) { p.Source = "private\nmarker" }, "invalid-text": func(p *ExperimentalV3Profile) { p.Source = string([]byte{255}) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			p := f.profile
			change(&p)
			if p.Validate() != ErrExperimentalV3Profile {
				t.Fatal("invalid profile accepted")
			}
			if s, err := NewExperimentalV3State(p, f.policy, f.schedule, f.pin); err == nil || s.data != nil {
				t.Fatal("invalid profile initialized state")
			}
		})
	}
	for _, p := range []ExperimentalV3Policy{{}, {W: 1, RetainHeaders: 1, MaxBatchHeaders: 1}, {W: 2, RetainHeaders: 2, MaxBatchHeaders: 3}, {W: 1, RetainHeaders: 4097, MaxBatchHeaders: 3}, {W: 1, RetainHeaders: 2}, {W: 1, RetainHeaders: 2, MaxBatchHeaders: 4097}} {
		if p.Validate() != ErrExperimentalV3Policy {
			t.Fatal("unbounded policy accepted")
		}
	}
	if err := (ExperimentalV3Policy{W: 4095, RetainHeaders: 4096, MaxBatchHeaders: 4096}).Validate(); err != nil {
		t.Fatal("exact bounded policy", err)
	}
	for _, bad := range []string{`{"w":1.5,"retain_headers":2,"max_batch_headers":3}`, `{"w":-1,"retain_headers":2,"max_batch_headers":3}`, `{"w":1,"retain_headers":4294967296,"max_batch_headers":3}`} {
		var p ExperimentalV3Policy
		if json.Unmarshal([]byte(bad), &p) == nil {
			t.Fatal("invalid integer policy accepted")
		}
	}
	for _, pin := range []chain.Hash{{}, {1}} {
		if s, err := NewExperimentalV3State(f.profile, f.policy, f.schedule, pin); err != ErrContextFingerprintMismatch || s.data != nil {
			t.Fatal("unselected context accepted", err)
		}
	}
}

func TestExperimentalV3ScheduleAndContextBinding(t *testing.T) {
	f := experimentalV3Inputs(t)
	for _, kind := range []string{"nil", "chain", "hash", "missing-entry", "too-many-entries", "too-many-ranges"} {
		t.Run(kind, func(t *testing.T) {
			local := experimentalV3Inputs(t)
			schedule := local.schedule
			switch kind {
			case "nil":
				schedule = nil
			case "chain":
				schedule.ChainID = 69
			case "hash":
				schedule.ScheduleHash[0] ^= 1
			case "missing-entry":
				schedule.Entries = schedule.Entries[:2]
			case "too-many-entries":
				schedule.Entries = make([]ProducerEntry, 4097)
			case "too-many-ranges":
				schedule.Coverage = make([]ProducerCoverage, 4097)
			}
			if _, err := ExperimentalV3ContextFor(local.profile, local.policy, schedule); !errors.Is(err, ErrExperimentalV3Schedule) {
				t.Fatal("invalid schedule accepted", err)
			}
		})
	}
	for _, change := range []func(*experimentalV3Fixture){
		func(v *experimentalV3Fixture) { v.profile.Genesis.HeaderHash[0] ^= 1 }, func(v *experimentalV3Fixture) { v.profile.Anchor.HeaderHash[0] ^= 1 },
		func(v *experimentalV3Fixture) { v.profile.FirstV3Height = 11 }, func(v *experimentalV3Fixture) { v.profile.ValidThrough = 15 },
		func(v *experimentalV3Fixture) { v.policy.RetainHeaders = 3 }, func(v *experimentalV3Fixture) { v.policy.MaxBatchHeaders = 2 },
	} {
		local := experimentalV3Inputs(t)
		change(&local)
		c, err := ExperimentalV3ContextFor(local.profile, local.policy, local.schedule)
		if err != nil || c.Fingerprint == f.pin {
			t.Fatal("substantive context substitution not bound", err)
		}
		if s, err := NewExperimentalV3State(local.profile, local.policy, local.schedule, f.pin); err != ErrContextFingerprintMismatch || !reflect.DeepEqual(s, ExperimentalV3State{}) {
			t.Fatal("old pin accepted changed settings", err)
		}
	}
}
