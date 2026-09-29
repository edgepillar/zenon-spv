package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func readVerificationReport(t *testing.T, command string, args []string, wantCode int) verificationReport {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runVerification(command, append([]string{"--json"}, args...), &stdout, &stderr)
	if code != wantCode || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, &stderr, &stdout)
	}
	var report verificationReport
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatalf("output contains more than one JSON value: %v", err)
	}
	if report.SchemaVersion != 1 || report.Command != command || report.ExitCode != code || report.Results == nil || report.StateTrust == nil || report.Caveats == nil {
		t.Fatalf("invalid report envelope: %+v", report)
	}
	for _, r := range report.Results {
		if r.Proven == nil || r.NotProven == nil || r.TrustAssumptions == nil {
			t.Fatalf("result arrays must be present, even when empty: %+v", r)
		}
	}
	return report
}

func assertReportOutcome(t *testing.T, r verificationReport, want string) {
	t.Helper()
	if r.Outcome == nil || *r.Outcome != want {
		t.Fatalf("want outcome=%s, got %+v", want, r)
	}
}

func TestJSONReportsNodeEvidenceAllCommands(t *testing.T) {
	for _, retained := range []bool{false, true} {
		f := nodeRetainedQueryFixture(t, true)
		check := unchangedQueryFile(t, f.statePath)
		bundle := f.bundle
		args := slices.Clone(f.args)
		if retained {
			args = append(args, "--retained-only")
		} else {
			bundle.Headers = f.headers
			args = append(args[:2:2], args[4:]...)
			writeQueryJSON(t, f.bundlePath, bundle)
		}
		for _, command := range []string{"verify-headers", "verify-commitment", "verify-segment", "verify-state-value"} {
			if retained && command == "verify-headers" {
				continue
			}
			wantCode := 0
			if command == "verify-state-value" {
				wantCode = 2
			}
			r := readVerificationReport(t, command, append(slices.Clone(args), "--show-context", f.bundlePath), wantCode)
			if r.Error != nil || r.Context == nil || r.Context.ProtocolProfile == nil || r.Context.Anchor != f.anchor || r.VerificationTip == nil || r.VerificationTip.Height != 4009 {
				t.Fatalf("missing captured settings or verified tip: %+v", r)
			}
			if retained {
				if r.Mode != "retained_only" || r.Persistence != "read_only" || !slices.Contains(r.StateTrust, verify.TrustPersistedState) {
					t.Fatal("retained query lost its read-only mode or local-state provenance")
				}
			} else if r.Mode != "extend" || r.Persistence != "not_requested" {
				t.Fatal("extension without --state reported persistence")
			}
			if wantCode == 0 {
				assertReportOutcome(t, r, "ACCEPT")
				if len(r.Caveats) != 2 {
					t.Fatal("successful report lost its profile or producer caveat")
				}
			} else {
				assertReportOutcome(t, r, "REFUSED")
			}
			rows := r.Results
			if !retained {
				if rows[0].Reference.Scope != "headers" || rows[0].Outcome != "ACCEPT" {
					t.Fatal("extension report omitted headers")
				}
				rows = rows[1:]
			}
			switch command {
			case "verify-headers":
				if len(rows) != 0 {
					t.Fatal("header command reported unexamined proofs")
				}
			case "verify-commitment", "verify-segment":
				if len(rows) != 5 {
					t.Fatalf("expected five node-derived inclusions, got %d", len(rows))
				}
				for i, row := range rows {
					if row.Outcome != "ACCEPT" || !reflect.DeepEqual(row.Proven, []verify.Guarantee{verify.GuaranteeContentInclusion}) {
						t.Fatalf("embedded block gained unsupported guarantees: %+v", row)
					}
					if row.Reference.AccountHeader == nil || *row.Reference.AccountHeader != f.bundle.Commitments[i].Target {
						t.Fatal("result bound to the wrong account header")
					}
					if command == "verify-commitment" {
						if row.Reference.Index == nil || *row.Reference.Index != i || row.Reference.MomentumHeight == nil || *row.Reference.MomentumHeight != 4003 {
							t.Fatal("commitment reference changed")
						}
					} else if row.Reference.Index == nil || *row.Reference.Index != 0 || row.Reference.BlockIndex == nil || *row.Reference.BlockIndex != i {
						t.Fatal("segment/block reference changed")
					}
				}
			case "verify-state-value":
				if len(rows) != 1 || rows[0].Reason != "ReasonUnsupportedStateCommitment" || len(rows[0].Proven) != 0 || !slices.Contains(rows[0].NotProven, verify.GuaranteeStateValueInclusion) {
					t.Fatal("state value acquired an accepting report")
				}
			}
			check(t)
		}
	}
}

func TestJSONReportMixedProofOutcomesAndSyntheticSegments(t *testing.T) {
	f := nodeRetainedQueryFixture(t, false)
	check := unchangedQueryFile(t, f.statePath)
	accepted := f.bundle.Commitments[0]
	refused, rejected := accepted, accepted
	refused.Height = math.MaxUint64
	rejected.Target.Hash[0] ^= 1
	for _, entries := range [][]proof.CommitmentEvidence{{accepted, refused, rejected}, {rejected, accepted, refused}} {
		bundle := f.bundle
		bundle.Commitments = entries
		writeQueryJSON(t, f.bundlePath, bundle)
		r := readVerificationReport(t, "verify-commitment", append(slices.Clone(f.args), "--retained-only", f.bundlePath), 1)
		assertReportOutcome(t, r, "REJECT")
		if len(r.Results) != 3 || r.Error != nil || r.Persistence != "read_only" {
			t.Fatal("mixed results changed severity or persistence")
		}
		for i, row := range r.Results {
			if row.Reference.Index == nil || *row.Reference.Index != i || row.Reference.MomentumHeight == nil || *row.Reference.MomentumHeight != entries[i].Height {
				t.Fatal("report lost exact input reference or uint64 height")
			}
		}
		check(t)
	}
	for _, n := range []int{0, verify.DefaultMaxSegmentBlocks + 1} {
		bundle := f.bundle
		bundle.Segments = []proof.AccountSegment{{Address: f.bundle.Segments[0].Address, Blocks: make([]chain.AccountBlock, n)}}
		writeQueryJSON(t, f.bundlePath, bundle)
		r := readVerificationReport(t, "verify-segment", append(slices.Clone(f.args), "--retained-only", f.bundlePath), 2)
		assertReportOutcome(t, r, "REFUSED")
		if len(r.Results) != 1 || r.Results[0].Reference.Scope != "segment" || r.Results[0].Reference.Index == nil || *r.Results[0].Reference.Index != 0 || r.Results[0].Reference.BlockIndex != nil || r.Results[0].Reference.AccountHeader != nil || r.Results[0].FailedAt != -1 {
			t.Fatal("synthetic segment refusal was attributed to a block")
		}
		check(t)
	}
}

func TestJSONReportEarlyOutcomesAndNoPersistence(t *testing.T) {
	for _, tc := range []struct {
		name, command, scope, reason string
		code                         int
		mutate                       func(*proof.HeaderBundle)
	}{
		{"chain", "verify-segment", "bundle", "ReasonChainIDMismatch", 1, func(b *proof.HeaderBundle) { b.ChainID++ }},
		{"anchor", "verify-headers", "bundle", "ReasonGenesisMismatch", 1, func(b *proof.HeaderBundle) { b.ClaimedGenesis[0] ^= 1 }},
		{"signature", "verify-segment", "headers", "ReasonInvalidSignature", 1, func(b *proof.HeaderBundle) { b.Headers[0].Signature[0] ^= 1 }},
		{"empty headers", "verify-commitment", "headers", "ReasonMissingEvidence", 2, func(b *proof.HeaderBundle) { b.Headers = nil }},
		{"empty commitments", "verify-commitment", "commitments", "ReasonMissingEvidence", 2, func(b *proof.HeaderBundle) { b.Commitments = nil }},
		{"empty segments", "verify-segment", "segments", "ReasonMissingEvidence", 2, func(b *proof.HeaderBundle) { b.Segments = nil }},
		{"empty state proofs", "verify-state-value", "state_value_proofs", "ReasonMissingEvidence", 2, func(b *proof.HeaderBundle) { b.StateValueProofs = nil }},
		{"aggregate segments", "verify-segment", "bundle", "ReasonOversizedSegment", 2, func(b *proof.HeaderBundle) { b.Segments = make([]proof.AccountSegment, verify.DefaultMaxSegments+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := nodeRetainedQueryFixture(t, false)
			bundle := f.bundle
			bundle.Headers = f.headers
			tc.mutate(&bundle)
			writeQueryJSON(t, f.bundlePath, bundle)
			statePath := filepath.Join(t.TempDir(), "state.json")
			args := append(slices.Clone(f.args[:2]), "--state", statePath, f.bundlePath)
			r := readVerificationReport(t, tc.command, args, tc.code)
			want := "REFUSED"
			if tc.code == 1 {
				want = "REJECT"
			}
			assertReportOutcome(t, r, want)
			last := r.Results[len(r.Results)-1]
			if r.Error != nil || r.Persistence != "not_attempted" || last.Reference.Scope != tc.scope || last.Reason != tc.reason || len(last.Proven) != 0 {
				t.Fatalf("failed verification gained proof or persistence: %+v", r)
			}
			if _, err := os.Stat(statePath); !os.IsNotExist(err) {
				t.Fatalf("failed verification created state: %v", err)
			}
		})
	}
}

func TestJSONReportOperationalFailuresAreNotVerificationOutcomes(t *testing.T) {
	f := nodeRetainedQueryFixture(t, false)
	privatePath := filepath.Join(t.TempDir(), "PRIVATE_PATH")
	for _, tc := range []struct {
		stage string
		args  []string
		code  int
	}{
		{"arguments", []string{"--window", "PRIVATE_TIER", f.bundlePath}, 64},
		{"arguments", []string{}, 64},
		{"arguments", []string{"--retained-only", f.bundlePath}, 64},
		{"genesis", []string{"--genesis-config", privatePath, f.bundlePath}, 70},
		{"protocol_profile", append(slices.Clone(f.args[:2]), "--protocol-profile", privatePath, f.bundlePath), 70},
		{"bundle", append(slices.Clone(f.args[:2]), privatePath), 70},
		{"schedule", append(slices.Clone(f.args[:2]), "--schedule", privatePath, f.bundlePath), 70},
		{"state", append(slices.Clone(f.args[:2]), "--state", f.bundlePath, f.bundlePath), 70},
	} {
		r := readVerificationReport(t, "verify-segment", tc.args, tc.code)
		if r.Outcome != nil || r.Error == nil || r.Error.Stage != tc.stage || len(r.Results) != 0 {
			t.Fatalf("operational failure reported a verification result: %+v", r)
		}
		raw, err := json.Marshal(r)
		if err != nil || bytes.Contains(raw, []byte("PRIVATE_")) || bytes.Contains(raw, []byte(privatePath)) {
			t.Fatal("private setup data reached the report")
		}
	}
	for _, args := range [][]string{{"--json", "--unknown-private-flag"}, {"--json=invalid"}, {"--help"}} {
		var stdout, stderr bytes.Buffer
		if code := runVerification("verify-headers", args, &stdout, &stderr); code != 64 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatal("syntax/help output must remain on stderr without a report")
		}
	}
}

func TestJSONReportPersistenceSuccessFailureAndOutputFailure(t *testing.T) {
	bundlePath, anchorPath := stateValueBundleFromLongChain(t, 6, nil)
	for _, name := range []string{"saved", "failed"} {
		t.Run(name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "state.json")
			code := 0
			if name == "failed" {
				statePath = unwritableReportStatePath(t)
				code = 70
			}
			r := readVerificationReport(t, "verify-headers", []string{"--genesis-config", anchorPath, "--state", statePath, bundlePath}, code)
			assertReportOutcome(t, r, "ACCEPT")
			if r.Persistence != name || name == "failed" && (r.Error == nil || r.Error.Stage != "persistence") || name == "saved" && r.Error != nil {
				t.Fatal("report confused persistence with accepted evidence")
			}
		})
	}
	for _, short := range []bool{false, true} {
		statePath := filepath.Join(t.TempDir(), "state.json")
		var stderr bytes.Buffer
		args := []string{"--json", "--genesis-config", anchorPath, "--state", statePath, bundlePath}
		code := runVerification("verify-headers", args, reportFailWriter{short: short}, &stderr)
		if code != 70 || stderr.String() != "report: cannot write JSON output\n" {
			t.Fatalf("output error was ignored or disclosed its cause: %d %s", code, &stderr)
		}
		anchor, err := verify.LoadGenesisFromConfig(anchorPath)
		if err != nil {
			t.Fatal(err)
		}
		state, err := verify.LoadTrustedState(statePath, anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()})
		if err != nil || state.Empty() {
			t.Fatalf("report failure rolled back or corrupted an already saved state: %v", err)
		}
	}
}

type reportFailWriter struct{ short bool }

func (w reportFailWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("PRIVATE_OUTPUT_ERROR")
}

func TestJSONFalsePreservesTextAndOmitsReport(t *testing.T) {
	bundlePath, anchorPath := stateValueBundleFromLongChain(t, 6, nil)
	for _, command := range []string{"verify-headers", "verify-commitment", "verify-segment", "verify-state-value"} {
		var plain, selected, plainErr, selectedErr bytes.Buffer
		args := []string{"--genesis-config", anchorPath, "--show-context", bundlePath}
		code := runVerification(command, args, &plain, &plainErr)
		other := runVerification(command, append([]string{"--json=false"}, args...), &selected, &selectedErr)
		if code != other || plain.String() != selected.String() || plainErr.String() != selectedErr.String() || strings.Contains(plain.String(), "\"exit_code\"") {
			t.Fatal("explicit false changed legacy output")
		}
	}
}

func TestJSONReportPrivateMetadataAndUntrustedProofStrings(t *testing.T) {
	f := nodeRetainedQueryFixture(t, false)
	profile := verify.ProtocolProfile{Version: 1, Anchor: f.anchor, ValidThrough: 4009,
		Source: "PRIVATE_PROFILE https://private.invalid/observation"}
	entries := make([]verify.ProducerEntry, len(f.headers))
	for i, h := range f.headers {
		entries[i] = verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.PublicKey)}
	}
	schedule, err := verify.NewProducerSchedule(f.anchor.ChainID,
		[]verify.ProducerCoverage{{FromHeight: 4001, ThroughHeight: 4009}}, entries,
		[]string{"PRIVATE_PEER"}, map[string]uint64{"PRIVATE_PEER": 4009})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	profilePath, schedulePath := filepath.Join(dir, "profile.json"), filepath.Join(dir, "schedule.json")
	writeQueryJSON(t, profilePath, profile)
	writeQueryJSON(t, schedulePath, schedule)
	bundle := f.bundle
	bundle.Headers = f.headers
	bundle.StateValueProofs[0].CommitmentKind = "PRIVATE_KIND\x1b[31m"
	bundle.StateValueProofs[0].Key = []byte("PRIVATE_KEY")
	bundle.StateValueProofs[0].ClaimedValue = []byte("PRIVATE_VALUE")
	writeQueryJSON(t, f.bundlePath, bundle)
	args := append(slices.Clone(f.args[:2]), "--protocol-profile", profilePath, "--schedule", schedulePath, f.bundlePath)
	r := readVerificationReport(t, "verify-state-value", args, 2)
	if r.Context == nil || r.Context.Producer.Kind != "schedule" || r.Context.Producer.ScheduleHash == nil || r.Context.ProtocolProfile == nil {
		t.Fatal("private metadata exclusion removed verification settings")
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{dir, f.bundlePath, "PRIVATE_", "private.invalid", "UFJJVkFURV9", `\u001b`} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatalf("report disclosed private data: %s", private)
		}
	}
}

func TestJSONReportBundleAndRetainedStateFailures(t *testing.T) {
	f := nodeRetainedQueryFixture(t, false)
	check := unchangedQueryFile(t, f.statePath)
	for _, raw := range []string{`{"version":1,"headers":[],"HEADERS":[]}`, `{"version":99}`, `PRIVATE_INVALID_JSON`} {
		if err := os.WriteFile(f.bundlePath, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		r := readVerificationReport(t, "verify-segment", append(slices.Clone(f.args), "--retained-only", f.bundlePath), 70)
		if r.Outcome != nil || r.Error == nil || r.Error.Stage != "bundle" || len(r.Results) != 0 {
			t.Fatal("invalid bundle acquired a verification result")
		}
		check(t)
	}
	file, err := os.Create(f.bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	err = file.Truncate(verify.DefaultMaxBundleBytes + 1)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("create oversized fixture: %v %v", err, closeErr)
	}
	r := readVerificationReport(t, "verify-segment", append(slices.Clone(f.args), "--retained-only", f.bundlePath), 2)
	if r.Error != nil || len(r.Results) != 1 || r.Results[0].Reason != "ReasonOversizedBundle" {
		t.Fatal("wire-size refusal was lost")
	}
	check(t)
	writeQueryJSON(t, f.bundlePath, f.bundle)
	args := append(slices.Clone(f.args[:2]), "--state", filepath.Join(t.TempDir(), "absent-state.json"), "--retained-only", f.bundlePath)
	r = readVerificationReport(t, "verify-segment", args, 2)
	if r.Error != nil || len(r.Results) != 1 || r.Results[0].Reference.Scope != "state" || r.Results[0].Reason != "ReasonMissingEvidence" || r.VerificationTip != nil {
		t.Fatal("missing retained state was not refused")
	}
	check(t)
}

// Precreate the lock in a directory that can be read but not replaced. The
// writer can take its existing lock and verify, then fail at the actual save.
func unwritableReportStatePath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if probe, err := os.CreateTemp(dir, "permission-probe-"); err == nil {
		_ = probe.Close()
		t.Skip("filesystem or process privileges allow writes in a read-only directory")
	}
	return path
}
