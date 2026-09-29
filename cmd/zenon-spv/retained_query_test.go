package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type retainedQueryFixture struct {
	bundle                proof.HeaderBundle
	anchor                verify.GenesisTrustRoot
	headers               []chain.Header
	args                  []string
	statePath, bundlePath string
}

func writeQueryJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func nodeRetainedQueryFixture(t *testing.T, withProfile bool) retainedQueryFixture {
	t.Helper()
	raw, err := os.ReadFile("../../internal/testdata/conformance/contract-batches.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Source struct{ Commit string }
		Chain  struct {
			Anchor  verify.GenesisTrustRoot
			Vectors []struct {
				Header  chain.Header
				Content []chain.AccountHeader
			}
		}
		Segments []struct {
			Address chain.Address
			Vectors []struct{ Block chain.AccountBlock }
		}
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Source.Commit != "3a4131e63881058b6ce2ee81d3a41d0033fafc99" || len(corpus.Chain.Vectors) != 9 || len(corpus.Segments) != 1 || len(corpus.Segments[0].Vectors) != 5 {
		t.Fatal("unexpected node contract corpus")
	}
	dir := t.TempDir()
	f := retainedQueryFixture{anchor: corpus.Chain.Anchor, statePath: filepath.Join(dir, "state.json"), bundlePath: filepath.Join(dir, "proof.json")}
	f.bundle = proof.HeaderBundle{Version: proof.WireVersion, ChainID: f.anchor.ChainID, ClaimedGenesis: f.anchor.HeaderHash}
	for _, v := range corpus.Chain.Vectors {
		f.headers = append(f.headers, v.Header)
		for _, target := range v.Content {
			f.bundle.Commitments = append(f.bundle.Commitments, proof.CommitmentEvidence{Height: v.Header.Height, Target: target, Flat: &proof.FlatContentEvidence{SortedHeaders: v.Content}})
		}
	}
	segment := proof.AccountSegment{Address: corpus.Segments[0].Address}
	for _, v := range corpus.Segments[0].Vectors {
		segment.Blocks = append(segment.Blocks, v.Block)
	}
	f.bundle.Segments = []proof.AccountSegment{segment}
	f.bundle.StateValueProofs = []proof.StateValueProof{{ChainID: f.anchor.ChainID, MomentumHeight: f.bundle.Commitments[0].Height,
		CommitmentKind: proof.StateCommitmentIAVLState, ProofNodes: [][]byte{{1}}}}
	anchorPath := filepath.Join(dir, "anchor.json")
	writeQueryJSON(t, anchorPath, f.anchor)
	f.args = []string{"--genesis-config", anchorPath, "--state", f.statePath}
	if withProfile {
		profilePath := filepath.Join(dir, "profile.json")
		writeQueryJSON(t, profilePath, verify.ProtocolProfile{Version: 1, Anchor: f.anchor, ValidThrough: f.headers[8].Height, Source: "synthetic retained-query profile"})
		f.args = append(f.args, "--protocol-profile", profilePath)
	}
	seed := f.bundle
	seed.Headers = f.headers
	writeQueryJSON(t, f.bundlePath, seed)
	if code, output := captureRun(t, func() int { return runVerifyHeaders(append(slices.Clone(f.args), f.bundlePath)) }); code != 0 {
		t.Fatalf("seed header verification failed: %d %s", code, output)
	}
	writeQueryJSON(t, f.bundlePath, f.bundle)
	return f
}

func unchangedQueryFile(t *testing.T, path string) func(*testing.T) {
	t.Helper()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1700000000, 0)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return func(t *testing.T) {
		t.Helper()
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("query changed file content: %v", err)
		}
		current, err := os.Stat(path)
		if err != nil || !os.SameFile(info, current) || !info.ModTime().Equal(current.ModTime()) || info.Mode() != current.Mode() {
			t.Fatalf("query replaced or rewrote a file: %v", err)
		}
	}
}

func queryProvenGuarantees(output string) []string {
	var claims []string
	proven := false
	for _, line := range strings.Split(output, "\n") {
		if line == "proven:" {
			proven = true
		} else if strings.HasPrefix(line, "  - ") {
			if proven {
				claims = append(claims, strings.TrimPrefix(line, "  - "))
			}
		} else {
			proven = false
		}
	}
	return claims
}

func queryHasAcceptedResult(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, ": ACCEPT ") || strings.HasPrefix(line, "ACCEPT ") {
			return true
		}
	}
	return false
}

func TestRetainedQueryNodeEvidenceAndReadOnlyState(t *testing.T) {
	for _, withProfile := range []bool{false, true} {
		f := nodeRetainedQueryFixture(t, withProfile)
		checkState := unchangedQueryFile(t, f.statePath)
		checkBundle := unchangedQueryFile(t, f.bundlePath)
		for name, run := range map[string]func([]string) int{
			"commitment": runVerifyCommitment, "segment": runVerifySegment, "state-value": runVerifyStateValue,
		} {
			mode := "legacy"
			if withProfile {
				mode = "profile"
			}
			t.Run(mode+"/"+name, func(t *testing.T) {
				args := append(slices.Clone(f.args), "--retained-only", "--show-context", f.bundlePath)
				code, output, diagnostics := captureSetupRun(t, func() int { return run(args) })
				wantCode := 0
				if name == "state-value" {
					wantCode = 2
					if !strings.Contains(output, "ReasonUnsupportedStateCommitment") {
						t.Fatal(output)
					}
				}
				if code != wantCode || !strings.Contains(output, "retained_state: height=4009") || strings.Contains(output, "headers: ACCEPT") {
					t.Fatalf("retained query: code=%d output=%s diagnostics=%s", code, output, diagnostics)
				}
				if !strings.Contains(output, string(verify.TrustPersistedState)) || !strings.Contains(output, string(verify.TrustConfiguredAnchor)) {
					t.Fatal("query omitted local-state trust")
				}
				context := readCLIContext(t, output)
				if (context.ProtocolProfile != nil) != withProfile {
					t.Fatal("query lost its activation policy")
				}
				claims := queryProvenGuarantees(output)
				if name == "state-value" {
					if len(claims) != 0 || queryHasAcceptedResult(output) {
						t.Fatal("state value query gained an accepting path")
					}
				} else {
					if len(claims) != 5 {
						t.Fatalf("expected five inclusion results, got %v", claims)
					}
					for _, claim := range claims {
						if claim != string(verify.GuaranteeContentInclusion) {
							t.Fatalf("query claimed more than embedded-block inclusion: %s", claim)
						}
					}
				}
				checkState(t)
				checkBundle(t)
			})
		}
	}
}

func TestRetainedQueryRequiresExplicitModeAndEmptyHeaders(t *testing.T) {
	f := nodeRetainedQueryFixture(t, false)
	check := unchangedQueryFile(t, f.statePath)
	for name, run := range map[string]func([]string) int{
		"commitment": runVerifyCommitment, "segment": runVerifySegment, "state-value": runVerifyStateValue,
	} {
		t.Run(name, func(t *testing.T) {
			// Without explicit selection, empty headers retain their refusal.
			for _, extra := range [][]string{nil, {"--retained-only=false"}} {
				args := append(append(slices.Clone(f.args), extra...), f.bundlePath)
				code, output := captureRun(t, func() int { return run(args) })
				if code != 2 || !strings.Contains(output, "ReasonMissingEvidence") || queryHasAcceptedResult(output) {
					t.Fatalf("empty input silently enabled retained queries: %d %s", code, output)
				}
			}
			// Even malformed supplied headers must not be silently discarded.
			bad := f.bundle
			bad.Headers = []chain.Header{{Version: 99}}
			badPath := filepath.Join(t.TempDir(), "with-headers.json")
			writeQueryJSON(t, badPath, bad)
			args := append(slices.Clone(f.args), "--retained-only", badPath)
			code, output, diagnostics := captureSetupRun(t, func() int { return run(args) })
			if code != 64 || !strings.Contains(diagnostics, "bundle with no headers") || queryHasAcceptedResult(output) {
				t.Fatalf("query ignored supplied headers: %d %s %s", code, output, diagnostics)
			}
			check(t)
		})
	}
	for name, run := range map[string]func([]string) int{"headers": runVerifyHeaders, "missing state flag": runVerifySegment} {
		t.Run(name, func(t *testing.T) {
			// Invalid mode combinations fail before any config/evidence file is read.
			args := []string{"--retained-only", "--genesis-config", "missing-anchor.json", "missing-proof.json"}
			if name == "headers" {
				args = []string{"--retained-only", "--state", f.statePath, "--genesis-config", "missing-anchor.json", "missing-proof.json"}
			}
			code, output, diagnostics := captureSetupRun(t, func() int { return run(args) })
			if code != 64 || !strings.Contains(diagnostics, "requires a proof command and --state") || queryHasAcceptedResult(output) {
				t.Fatalf("invalid query mode reached verification: %d %s %s", code, output, diagnostics)
			}
			check(t)
		})
	}
}

func TestRetainedQueryProofFailuresDoNotChangeState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*proof.HeaderBundle)
		extra  []string
		code   int
		reason verify.ReasonCode
	}{
		{"missing proof", func(b *proof.HeaderBundle) { b.Commitments = nil }, nil, 2, verify.ReasonMissingProof},
		{"wrong chain", func(b *proof.HeaderBundle) { b.ChainID++ }, nil, 1, verify.ReasonChainIDMismatch},
		{"evicted target", func(b *proof.HeaderBundle) { b.Commitments[0].Height = 4002 }, nil, 2, verify.ReasonHeightOutOfWindow},
		{"shallow target", func(b *proof.HeaderBundle) { b.Commitments[0].Height = 4004 }, nil, 2, verify.ReasonInsufficientFinality},
		{"stronger depth", func(*proof.HeaderBundle) {}, []string{"--window", "medium"}, 2, verify.ReasonInsufficientFinality},
		{"tampered flat", func(b *proof.HeaderBundle) {
			b.Commitments[0].Flat.SortedHeaders = b.Commitments[0].Flat.SortedHeaders[1:]
		}, nil, 1, verify.ReasonInvalidContent},
		{"tampered block", func(b *proof.HeaderBundle) { b.Segments[0].Blocks[0].DataHash[0] ^= 1 }, nil, 1, verify.ReasonInvalidHash},
		{"oversized evidence", func(b *proof.HeaderBundle) {
			b.Commitments = make([]proof.CommitmentEvidence, verify.DefaultMaxCommitments+1)
		}, nil, 2, verify.ReasonOversizedEvidence},
		{"missing segment", func(b *proof.HeaderBundle) { b.Segments = nil }, nil, 2, verify.ReasonMissingEvidence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := nodeRetainedQueryFixture(t, false)
			check := unchangedQueryFile(t, f.statePath)
			tc.edit(&f.bundle)
			writeQueryJSON(t, f.bundlePath, f.bundle)
			args := append(append(slices.Clone(f.args), tc.extra...), "--retained-only", f.bundlePath)
			code, output := captureRun(t, func() int { return runVerifySegment(args) })
			if code != tc.code || !strings.Contains(output, tc.reason.String()) || queryHasAcceptedResult(output) || len(queryProvenGuarantees(output)) != 0 {
				t.Fatalf("query failure gained acceptance: code=%d output=%s", code, output)
			}
			check(t)
		})
	}
}

func TestRetainedQueryRequiresValidNonemptyState(t *testing.T) {
	for _, mode := range []string{"missing", "empty", "bad signature", "wrong anchor"} {
		t.Run(mode, func(t *testing.T) {
			f := nodeRetainedQueryFixture(t, false)
			wantCode := 70
			switch mode {
			case "missing":
				if err := os.Remove(f.statePath); err != nil {
					t.Fatal(err)
				}
				wantCode = 2
			case "empty":
				state, err := verify.NewVerifiedState(f.anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()})
				if err != nil {
					t.Fatal(err)
				}
				if err := state.Save(f.statePath); err != nil {
					t.Fatal(err)
				}
				wantCode = 2
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
			}
			var check func(*testing.T)
			if mode != "missing" {
				check = unchangedQueryFile(t, f.statePath)
			}
			code, output := captureRun(t, func() int { return runVerifySegment(append(slices.Clone(f.args), "--retained-only", f.bundlePath)) })
			if code != wantCode || queryHasAcceptedResult(output) || strings.Contains(output, "retained_state:") {
				t.Fatalf("invalid saved state reached query evaluation: %d %s", code, output)
			}
			if check != nil {
				check(t)
			} else if _, err := os.Stat(f.statePath); !os.IsNotExist(err) {
				t.Fatalf("missing query state was created: %v", err)
			}
		})
	}
}

func TestRetainedQueryReauthorizesProducersAndKeepsProfile(t *testing.T) {
	for _, mode := range []string{"authorized", "unauthorized", "uncovered", "missing profile"} {
		t.Run(mode, func(t *testing.T) {
			f := nodeRetainedQueryFixture(t, true)
			check := unchangedQueryFile(t, f.statePath)
			args := slices.Clone(f.args)
			wantCode, wantReason := 0, verify.ReasonOK.String()
			if mode == "missing profile" {
				args = args[:len(args)-2]
				wantCode, wantReason = 70, ""
			} else {
				var entries []verify.ProducerEntry
				for _, h := range f.headers[2:] {
					entries = append(entries, verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
				}
				switch mode {
				case "unauthorized":
					entries[0].ProducingAddr[0] ^= 1
					wantCode, wantReason = 1, verify.ReasonUnauthorizedProducer.String()
				case "uncovered":
					entries = entries[1:]
					wantCode, wantReason = 2, verify.ReasonProducerSetUnknown.String()
				}
				coverage := []verify.ProducerCoverage{{FromHeight: entries[0].Height, ThroughHeight: entries[len(entries)-1].Height}}
				schedule, err := verify.NewProducerSchedule(f.anchor.ChainID, coverage, entries, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				schedulePath := filepath.Join(t.TempDir(), "schedule.json")
				writeQueryJSON(t, schedulePath, schedule)
				args = append(args, "--schedule", schedulePath)
			}
			code, output := captureRun(t, func() int { return runVerifyCommitment(append(args, "--retained-only", f.bundlePath)) })
			if code != wantCode || !strings.Contains(output, wantReason) || (code != 0 && queryHasAcceptedResult(output)) {
				t.Fatalf("query changed producer/profile policy: %d %s", code, output)
			}
			if code == 0 && (!strings.Contains(output, string(verify.TrustExternalProducerSchedule)) || !strings.Contains(output, string(verify.TrustExternalProtocolProfile))) {
				t.Fatal("query omitted external policy provenance")
			}
			check(t)
		})
	}
}

func TestRetainedQueryDoesNotPersistWindowTruncation(t *testing.T) {
	f := nodeRetainedQueryFixture(t, false)
	policy := verify.DefaultPolicy()
	policy.W = 8
	initial, err := verify.NewVerifiedState(f.anchor, verify.VerifyOptions{Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	r, larger := initial.Extend(f.headers)
	if r.Outcome != verify.OutcomeAccept || len(larger.Snapshot().RetainedWindow) != 9 {
		t.Fatal("could not seed the larger retained window")
	}
	if err := larger.Save(f.statePath); err != nil {
		t.Fatal(err)
	}
	check := unchangedQueryFile(t, f.statePath)
	// The default query policy loads only seven of the nine stored headers.
	code, output := captureRun(t, func() int {
		return runVerifySegment(append(slices.Clone(f.args), "--retained-only", f.bundlePath))
	})
	if code != 0 || len(queryProvenGuarantees(output)) != 5 {
		t.Fatalf("query under the smaller policy failed: %d %s", code, output)
	}
	check(t)
	saved, err := verify.LoadHeaderState(f.statePath)
	if err != nil || len(saved.RetainedWindow) != 9 {
		t.Fatalf("read-only query persisted the smaller window: %v", err)
	}
}

func TestRetainedQueryRejectsOverwrittenHeaders(t *testing.T) {
	f := nodeRetainedQueryFixture(t, false)
	check := unchangedQueryFile(t, f.statePath)
	raw, err := json.Marshal(f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"headers"`, `"HEADERS"`, `"heade\u0072s"`, `"headerſ"`} {
		t.Run(key, func(t *testing.T) {
			// A later null must not hide supplied invalid headers from the mode gate.
			bad := append([]byte("{"+key+`:[{"version":99}],`), raw[1:]...)
			if err := os.WriteFile(f.bundlePath, bad, 0o600); err != nil {
				t.Fatal(err)
			}
			code, output, diagnostics := captureSetupRun(t, func() int {
				return runVerifySegment(append(slices.Clone(f.args), "--retained-only", f.bundlePath))
			})
			if code != 70 || !strings.Contains(diagnostics, "duplicate bundle field") || queryHasAcceptedResult(output) {
				t.Fatalf("overwritten headers bypassed explicit mode: %d %s %s", code, output, diagnostics)
			}
			check(t)
		})
	}
}
