package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/statelock"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func inspectionFixture(t *testing.T, profile bool) retainedQueryFixture {
	t.Helper()
	f := nodeRetainedQueryFixture(t, profile)
	raw, err := os.ReadFile(f.statePath)
	if err != nil {
		t.Fatal(err)
	}
	// This copy has no preexisting writer companion, so inspection cannot hide
	// an accidental lock creation behind the seed command's own lock file.
	f.statePath = filepath.Join(filepath.Dir(f.statePath), "PRIVATE_STATE.json")
	f.args[3] = f.statePath
	if err := os.WriteFile(f.statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func inspectionJSON(t *testing.T, args []string, code int) stateInspectionReport {
	t.Helper()
	var out, diagnostics bytes.Buffer
	got := runInspectState(append([]string{"--json"}, args...), &out, &diagnostics)
	if got != code || diagnostics.Len() != 0 || bytes.Contains(out.Bytes(), []byte("PRIVATE")) {
		t.Fatalf("inspection failed or disclosed private diagnostics: code=%d want=%d stderr=%q", got, code, diagnostics.String())
	}
	var report stateInspectionReport
	decoder := json.NewDecoder(&out)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF || report.SchemaVersion != 1 || report.Command != "inspect-state" || report.ExitCode != code || report.Persistence != "read_only" {
		t.Fatal("inspection identity, framing, or persistence mismatch")
	}
	if code != 0 && (report.Context != nil || report.Window != nil || len(report.StateTrust) != 0) {
		t.Fatal("failed inspection exposed an authorized state")
	}
	return report
}

func TestInspectStateNodeWindowIsReadOnly(t *testing.T) {
	f := inspectionFixture(t, true)
	check := unchangedQueryFile(t, f.statePath)
	for _, tier := range []string{"low", "medium", "high"} {
		r := inspectionJSON(t, append(slices.Clone(f.args), "--window", tier), 0)
		w := r.Window
		if r.Status != "inspected" || r.Reason != nil || r.Error != nil || w == nil || w.Count != 7 ||
			w.Oldest.Height != 4003 || w.Tip.Height != 4009 || w.Oldest.Hash != f.headers[2].HeaderHash || w.Tip.Hash != f.headers[8].HeaderHash ||
			r.Context.Anchor != f.anchor || r.Context.ProtocolProfile == nil || len(r.Caveats) < 3 ||
			!slices.Contains(r.StateTrust, verify.TrustPersistedState) || !slices.Contains(r.StateTrust, verify.TrustExternalProtocolProfile) {
			t.Fatalf("node-derived inspection or provenance mismatch: %+v", r)
		}
		if w.Capacity != int(verify.PolicyForTier(tier).W)+1 || r.Context.Policy.W != verify.PolicyForTier(tier).W {
			t.Fatal("inspection ignored the selected policy")
		}
		if tier == "low" {
			if w.DepthEligible == nil || *w.DepthEligible != (verify.RetainedDepthRange{FromHeight: 4003, ThroughHeight: 4003}) {
				t.Fatal("low-depth inspection reported the wrong range")
			}
		} else if w.DepthEligible != nil {
			t.Fatal("stronger policy claimed unavailable depth")
		}
		check(t)
	}
	if _, err := os.Stat(f.statePath + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("read-only inspection created a writer companion: %v", err)
	}
	lock, err := statelock.Acquire(f.statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	inspectionJSON(t, f.args, 0)
	check(t)
	if other, err := statelock.Acquire(f.statePath); err == nil {
		_ = other.Close()
		t.Fatal("inspection released the active writer's lock")
	}
}

func TestInspectStateRequiresValidNonemptyState(t *testing.T) {
	for _, mode := range []string{"missing", "empty", "malformed", "bad signature", "wrong anchor", "missing profile"} {
		t.Run(mode, func(t *testing.T) {
			f := inspectionFixture(t, mode == "missing profile")
			code := 70
			switch mode {
			case "missing":
				f.statePath = filepath.Join(t.TempDir(), "PRIVATE_MISSING.json")
				f.args[3] = f.statePath
				code = 2
			case "empty":
				state, err := verify.NewVerifiedState(f.anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()})
				if err != nil {
					t.Fatal(err)
				}
				if err := state.Save(f.statePath); err != nil {
					t.Fatal(err)
				}
				code = 2
			case "malformed":
				if err := os.WriteFile(f.statePath, []byte("PRIVATE_INVALID_JSON"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "bad signature":
				raw, err := os.ReadFile(f.statePath)
				if err != nil {
					t.Fatal(err)
				}
				var saved map[string]json.RawMessage
				if err := json.Unmarshal(raw, &saved); err != nil {
					t.Fatal(err)
				}
				var headers []chain.Header
				if err := json.Unmarshal(saved["retained_window"], &headers); err != nil {
					t.Fatal(err)
				}
				headers[0].Signature[0] ^= 1
				if saved["retained_window"], err = json.Marshal(headers); err != nil {
					t.Fatal(err)
				}
				writeQueryJSON(t, f.statePath, saved)
			case "wrong anchor":
				f.anchor.HeaderHash[0] ^= 1
				writeQueryJSON(t, f.args[1], f.anchor)
			case "missing profile":
				f.args = f.args[:4]
			}
			var check func(*testing.T)
			if mode != "missing" {
				check = unchangedQueryFile(t, f.statePath)
			}
			r := inspectionJSON(t, f.args, code)
			if code == 2 {
				if r.Status != "refused" || r.Reason == nil || *r.Reason != verify.ReasonMissingEvidence.String() || r.Error != nil {
					t.Fatal("missing evidence lost its refusal classification")
				}
			} else if r.Status != "error" || r.Error == nil || r.Error.Stage != "state" {
				t.Fatal("invalid state reached inspection")
			}
			if check != nil {
				check(t)
			} else if _, err := os.Stat(f.statePath); !os.IsNotExist(err) {
				t.Fatal("inspection initialized a missing state")
			}
			if _, err := os.Stat(f.statePath + ".lock"); !os.IsNotExist(err) {
				t.Fatal("failed inspection created a writer companion")
			}
		})
	}
}

func TestInspectStateReauthorizesProducerSchedule(t *testing.T) {
	for _, mode := range []string{"authorized", "unauthorized", "uncovered"} {
		t.Run(mode, func(t *testing.T) {
			f := inspectionFixture(t, true)
			check := unchangedQueryFile(t, f.statePath)
			var entries []verify.ProducerEntry
			for _, h := range f.headers[2:] {
				entries = append(entries, verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
			}
			code, reason := 0, ""
			switch mode {
			case "unauthorized":
				entries[0].ProducingAddr[0] ^= 1
				code, reason = 1, verify.ReasonUnauthorizedProducer.String()
			case "uncovered":
				entries = entries[1:]
				code, reason = 2, verify.ReasonProducerSetUnknown.String()
			}
			schedule, err := verify.NewProducerSchedule(f.anchor.ChainID,
				[]verify.ProducerCoverage{{FromHeight: entries[0].Height, ThroughHeight: entries[len(entries)-1].Height}}, entries, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "PRIVATE_SCHEDULE.json")
			writeQueryJSON(t, path, schedule)
			r := inspectionJSON(t, append(slices.Clone(f.args), "--schedule", path), code)
			if code == 0 {
				if r.Context.Producer.Mode != "Required" || r.Context.Producer.ScheduleHash == nil || *r.Context.Producer.ScheduleHash != schedule.ScheduleHash || !slices.Contains(r.StateTrust, verify.TrustExternalProducerSchedule) {
					t.Fatal("inspection omitted the required producer policy")
				}
			} else if r.Reason == nil || *r.Reason != reason || r.Error != nil || (code == 1 && r.Status != "rejected") || (code == 2 && r.Status != "refused") {
				t.Fatal("authorization outcome changed during inspection")
			}
			check(t)
		})
	}
}

func TestInspectStateDoesNotPersistSmallerWindow(t *testing.T) {
	f := inspectionFixture(t, false)
	policy := verify.DefaultPolicy()
	policy.W = 8
	state, err := verify.NewVerifiedState(f.anchor, verify.VerifyOptions{Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	r, state := state.Extend(f.headers)
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	if err := state.Save(f.statePath); err != nil {
		t.Fatal(err)
	}
	check := unchangedQueryFile(t, f.statePath)
	report := inspectionJSON(t, f.args, 0)
	if report.Window.Count != 7 || report.Window.Capacity != 7 || report.Window.Oldest.Height != 4003 {
		t.Fatal("inspection did not use the effective policy window")
	}
	check(t)
	saved, err := verify.LoadHeaderState(f.statePath)
	if err != nil || len(saved.RetainedWindow) != 9 || saved.Capacity != 9 {
		t.Fatal("inspection persisted its smaller window")
	}
}

func TestInspectStateArgumentsAndPrivateErrors(t *testing.T) {
	f := inspectionFixture(t, false)
	set := func(name, value string) []string {
		args := slices.Clone(f.args)
		if i := slices.Index(args, name); i >= 0 {
			args[i+1] = value
			return args
		}
		return append(args, name, value)
	}
	for _, tc := range []struct {
		args  []string
		code  int
		stage string
	}{
		{nil, 64, "arguments"},
		{[]string{"--state="}, 64, "arguments"},
		{append(slices.Clone(f.args), "PRIVATE_POSITIONAL"), 64, "arguments"},
		{append(slices.Clone(f.args), "--window", "PRIVATE_TIER"), 64, "arguments"},
		{append(slices.Clone(f.args), "--PRIVATE_UNKNOWN"), 64, "arguments"},
		{set("--genesis-config", "PRIVATE_MISSING"), 70, "genesis"},
		{set("--protocol-profile", "PRIVATE_MISSING"), 70, "protocol_profile"},
		{set("--schedule", "PRIVATE_MISSING"), 70, "schedule"},
	} {
		r := inspectionJSON(t, tc.args, tc.code)
		if r.Status != "error" || r.Error == nil || r.Error.Stage != tc.stage {
			t.Fatal("inspection failure lost its stage")
		}
		var out, diagnostics bytes.Buffer
		if code := runInspectState(tc.args, &out, &diagnostics); code != tc.code || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE") {
			t.Fatal("text error disclosed an input or reached normal output")
		}
	}
	var out, diagnostics bytes.Buffer
	if code := runInspectState([]string{"--help"}, &out, &diagnostics); code != 0 || out.String() != inspectStateUsage || diagnostics.Len() != 0 {
		t.Fatal("inspection help requires state or changed its exit code")
	}
}

func TestInspectStateTextAndOutputFailures(t *testing.T) {
	f := inspectionFixture(t, false)
	check := unchangedQueryFile(t, f.statePath)
	var plain, selected, diagnostics bytes.Buffer
	if runInspectState(f.args, &plain, &diagnostics) != 0 || runInspectState(append([]string{"--json=false"}, f.args...), &selected, &diagnostics) != 0 || diagnostics.Len() != 0 || !reflect.DeepEqual(plain.Bytes(), selected.Bytes()) || !strings.Contains(plain.String(), "INSPECTED") || strings.Contains(plain.String(), "ACCEPT") {
		t.Fatal("text inspection became a proof result or changed with --json=false")
	}
	for _, want := range []string{
		"oldest: 4003 " + hex.EncodeToString(f.headers[2].HeaderHash[:]) + "\n",
		"tip: 4009 " + hex.EncodeToString(f.headers[8].HeaderHash[:]) + "\n",
	} {
		if !strings.Contains(plain.String(), want) {
			t.Fatal("text inspection did not render a full hexadecimal header identity")
		}
	}
	for _, jsonFlag := range []string{"--json", "--json=false"} {
		for _, short := range []bool{false, true} {
			diagnostics.Reset()
			if runInspectState(append([]string{jsonFlag}, f.args...), reportFailWriter{short: short}, &diagnostics) != 70 || diagnostics.String() != "inspect-state: cannot write report\n" {
				t.Fatal("failed output was successful or exposed the raw error")
			}
			check(t)
		}
	}
}
