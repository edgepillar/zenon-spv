package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func fixtureContext(t testing.TB, name string) settings {
	t.Helper()
	raw, err := os.ReadFile("../../internal/testdata/verification-context/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var c settings
	if !decodeExact(raw, &c) || !validContext(c) {
		t.Fatal("published independently checked context was not recognized")
	}
	return c
}

func matchingInputs(t testing.TB) (queryReport, expectations) {
	t.Helper()
	c := fixtureContext(t, "v1")
	h := uint64(math.MaxUint64)
	ref := reference{Scope: "commitment", MomentumHeight: &h,
		Account: accountHeader{Address: strings.Repeat("1", 40), Height: h, Hash: strings.Repeat("2", 64)}}
	trust := []string{"TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_RETAINED_WINDOW_DEPTH"}
	r := queryReport{Version: 1, Command: "verify-commitment", Mode: "retained_only", Outcome: "ACCEPT", Persistence: "read_only",
		Context: c, Tip: hashHeight{Hash: strings.Repeat("3", 64), Height: h}, StateTrust: slices.Clone(trust),
		Results: []row{{Reference: ref, Outcome: "ACCEPT", Reason: "ReasonOK", FailedAt: -1,
			Proven: []string{inclusion}, NotProven: []string{"CANONICALITY", "STATE_VALUE_INCLUSION"}, Trust: slices.Clone(trust)}},
		Caveats: []string{"PRIVATE_ENDPOINT"}}
	e := expectations{Version: 1, Command: r.Command, Context: c.Fingerprint, Tip: r.Tip,
		Targets: []reference{ref}, Required: []string{inclusion}, AllowedTrust: slices.Clone(trust)}
	return r, e
}

func encode(t testing.TB, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPublishedContextFingerprints(t *testing.T) {
	for _, name := range []string{"v1", "v2-retention", "v1-schedule-checkpoints"} {
		t.Run(name, func(t *testing.T) {
			c := fixtureContext(t, name)
			c.Policy.W++
			if validContext(c) {
				t.Fatal("changed settings retained an old diagnostic fingerprint")
			}
		})
	}
}

func TestQueryReportDecoding(t *testing.T) {
	r, expected := matchingInputs(t)
	raw := encode(t, r)
	var decoded queryReport
	if !decodeExact(raw, &decoded) || !validReport(decoded) || !validExpectations(expected) || matchReport(decoded, expected) != "" ||
		decoded.Tip.Height != math.MaxUint64 || decoded.Results[0].Reference.Account.Height != math.MaxUint64 {
		t.Fatal("lossless whole-batch matching failed")
	}
	for name, mutate := range map[string]func(string) string{
		"duplicate": func(s string) string {
			return strings.Replace(s, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)
		},
		"escaped duplicate": func(s string) string {
			return strings.Replace(s, `"schema_version":1`, `"schema_version":1,"schema_vers\u0069on":1`, 1)
		},
		"case alias":   func(s string) string { return strings.Replace(s, `"exit_code":0`, `"Exit_Code":0`, 1) },
		"nested alias": func(s string) string { return strings.Replace(s, `"chain_id":3`, `"Chain_ID":3`, 1) },
		"unknown": func(s string) string {
			return strings.Replace(s, `"exit_code":0`, `"exit_code":0,"PRIVATE_FIELD":0`, 1)
		},
		"missing zero":      func(s string) string { return strings.Replace(s, `"index":0,`, ``, 1) },
		"null zero":         func(s string) string { return strings.Replace(s, `"index":0`, `"index":null`, 1) },
		"null array":        func(s string) string { return strings.Replace(s, `"proven":["CONTENT_INCLUSION"]`, `"proven":null`, 1) },
		"null optional":     func(s string) string { return strings.Replace(s, `"index":0`, `"index":0,"block_index":null`, 1) },
		"float":             func(s string) string { return strings.Replace(s, `"exit_code":0`, `"exit_code":0.0`, 1) },
		"exponent":          func(s string) string { return strings.Replace(s, `"exit_code":0`, `"exit_code":0e0`, 1) },
		"negative zero":     func(s string) string { return strings.Replace(s, `"exit_code":0`, `"exit_code":-0`, 1) },
		"unsigned overflow": func(s string) string { return strings.ReplaceAll(s, `18446744073709551615`, `18446744073709551616`) },
		"unsigned negative": func(s string) string { return strings.ReplaceAll(s, `18446744073709551615`, `-1`) },
		"quoted integer":    func(s string) string { return strings.Replace(s, `"exit_code":0`, `"exit_code":"0"`, 1) },
		"second value":      func(s string) string { return s + `{}` },
		"truncated":         func(s string) string { return s[:len(s)-1] },
		"long string":       func(s string) string { return strings.Replace(s, `PRIVATE_ENDPOINT`, strings.Repeat("x", 4097), 1) },
		"large array": func(s string) string {
			return strings.Replace(s, `"PRIVATE_ENDPOINT"`, strings.TrimSuffix(strings.Repeat(`"x",`, 257), ","), 1)
		},
		"deep":         func(s string) string { return strings.Repeat("[", 17) + s + strings.Repeat("]", 17) },
		"invalid UTF8": func(s string) string { return strings.Replace(s, `PRIVATE_ENDPOINT`, string([]byte{0xff}), 1) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := mutate(string(raw))
			if candidate == string(raw) {
				t.Fatal("mutation did not exercise its case")
			}
			if decodeExact([]byte(candidate), new(queryReport)) {
				t.Fatal("ambiguous, incomplete or oversized shape decoded")
			}
		})
	}
}

func TestWholeBatchContract(t *testing.T) {
	for name, mutate := range map[string]func(*queryReport, *expectations){
		"wrong account": func(r *queryReport, _ *expectations) { r.Results[0].Reference.Account.Height-- },
		"wrong confirmation": func(r *queryReport, _ *expectations) {
			h := *r.Results[0].Reference.MomentumHeight - 1
			r.Results[0].Reference.MomentumHeight = &h
		},
		"extra result": func(r *queryReport, _ *expectations) {
			other := r.Results[0]
			other.Reference.Index = 1
			r.Results = append(r.Results, other)
		},
		"duplicate result":      func(r *queryReport, _ *expectations) { r.Results = append(r.Results, r.Results[0]) },
		"duplicate expectation": func(_ *queryReport, e *expectations) { e.Targets = append(e.Targets, e.Targets[0]) },
		"empty batch":           func(_ *queryReport, e *expectations) { e.Targets = []reference{} },
		"different tip":         func(_ *queryReport, e *expectations) { e.Tip.Height-- },
		"different context":     func(_ *queryReport, e *expectations) { e.Context = strings.Repeat("4", 64) },
		"changed context field": func(r *queryReport, _ *expectations) { r.Context.Policy.W++ },
		"extend mode":           func(r *queryReport, _ *expectations) { r.Mode = "extend" },
		"saved":                 func(r *queryReport, _ *expectations) { r.Persistence = "saved" },
		"failed exit":           func(r *queryReport, _ *expectations) { r.ExitCode = 70 },
		"refused row":           func(r *queryReport, _ *expectations) { r.Results[0].Outcome = "REFUSED" },
		"wrong reason":          func(r *queryReport, _ *expectations) { r.Results[0].Reason = "ReasonMissingEvidence" },
		"unproven inclusion": func(r *queryReport, _ *expectations) {
			r.Results[0].Proven = []string{}
			r.Results[0].NotProven = append(r.Results[0].NotProven, inclusion)
		},
		"conflicting guarantees": func(r *queryReport, _ *expectations) {
			r.Results[0].NotProven = append(r.Results[0].NotProven, inclusion)
		},
		"canonicality required":      func(_ *queryReport, e *expectations) { e.Required = append(e.Required, "CANONICALITY") },
		"state values required":      func(_ *queryReport, e *expectations) { e.Required = append(e.Required, "STATE_VALUE_INCLUSION") },
		"missing required guarantee": func(_ *queryReport, e *expectations) { e.Required = append(e.Required, "SIGNATURE_AUTHENTICITY") },
		"unknown trust":              func(r *queryReport, _ *expectations) { r.StateTrust = append(r.StateTrust, "UNKNOWN_TRUST") },
		"state trust not allowed":    func(r *queryReport, _ *expectations) { r.StateTrust = append(r.StateTrust, "TRUST_RPC_QUORUM") },
		"row trust not allowed": func(r *queryReport, _ *expectations) {
			r.Results[0].Trust = append(r.Results[0].Trust, "TRUST_RPC_QUORUM")
		},
		"lost persisted state trust": func(r *queryReport, _ *expectations) { r.StateTrust = []string{"TRUST_CONFIGURED_ANCHOR"} },
		"uppercase identity":         func(r *queryReport, _ *expectations) { r.Results[0].Reference.Account.Hash = strings.Repeat("A", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			r, e := matchingInputs(t)
			mutate(&r, &e)
			if validReport(r) && validExpectations(e) && matchReport(r, e) == "" {
				t.Fatal("incomplete or different query was matched")
			}
		})
	}
}

func TestConsumerBatchLimit(t *testing.T) {
	r, e := matchingInputs(t)
	first := r.Results[0]
	r.Results, e.Targets = nil, nil
	for i := 0; i < maxTargets; i++ {
		item := first
		item.Reference.Index = uint64(i)
		r.Results = append(r.Results, item)
		e.Targets = append(e.Targets, item.Reference)
	}
	var report queryReport
	var expected expectations
	if !decodeExact(encode(t, r), &report) || !decodeExact(encode(t, e), &expected) || !validReport(report) || !validExpectations(expected) || matchReport(report, expected) != "" {
		t.Fatal("maximum supported batch was refused")
	}
	if matchReport(report, expectations{Version: 1, Command: e.Command, Context: e.Context, Tip: e.Tip, Targets: e.Targets[:maxTargets-1], Required: e.Required, AllowedTrust: e.AllowedTrust}) == "" {
		t.Fatal("a subset matched the complete batch")
	}
	r.Results = append(r.Results, first)
	if decodeExact(encode(t, r), new(queryReport)) {
		t.Fatal("batch above the supported array bound decoded")
	}
}

func TestConsumerIOAndPrivacy(t *testing.T) {
	r, e := matchingInputs(t)
	dir := t.TempDir()
	reportPath, expectedPath := filepath.Join(dir, "PRIVATE_REPORT.json"), filepath.Join(dir, "PRIVATE_EXPECTATIONS.json")
	for path, raw := range map[string][]byte{reportPath: encode(t, r), expectedPath: encode(t, e)} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"--report", reportPath, "--expectations", expectedPath, "--verifier-exit-code", "0"}
	var out, diagnostics bytes.Buffer
	if code := run(args, &out, &diagnostics); code != 0 || out.String() != "{\"schema_version\":1,\"status\":\"matched\",\"category\":null,\"checked_targets\":1}\n" || diagnostics.Len() != 0 {
		t.Fatal("matching process did not produce the fixed summary")
	}
	for _, status := range []string{"1", "2", "64", "70", "141", "3221225786", "-1073741819", "-1"} {
		out.Reset()
		diagnostics.Reset()
		failed := slices.Clone(args)
		failed[len(failed)-1] = status
		if run(failed, &out, &diagnostics) != 2 || !strings.Contains(out.String(), `"category":"process_failure"`) || strings.Contains(out.String()+diagnostics.String(), "PRIVATE") {
			t.Fatal("complete ACCEPT report overrode actual process failure")
		}
	}
	for _, bad := range [][]string{{"--PRIVATE_FLAG"}, {"--verifier-exit-code", "PRIVATE_CODE"}, args[:len(args)-2], append(slices.Clone(args), "PRIVATE_POSITIONAL")} {
		out.Reset()
		diagnostics.Reset()
		if run(bad, &out, &diagnostics) != 64 || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE") {
			t.Fatal("usage error leaked an argument")
		}
	}
	for _, short := range []bool{false, true} {
		diagnostics.Reset()
		if run(args, brokenOutput{short}, &diagnostics) != 70 || strings.Contains(diagnostics.String(), "PRIVATE") {
			t.Fatal("failed summary output reported success or exposed a path")
		}
	}
	for path, limit := range map[string]int64{reportPath: maxReportBytes, expectedPath: maxExpectationsBytes} {
		if _, err := readInput(path, limit); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, bytes.Repeat([]byte{' '}, int(limit)+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readInput(path, limit); err == nil {
			t.Fatal("oversized file was read")
		}
	}
	if _, err := readInput(dir, maxReportBytes); err == nil {
		t.Fatal("directory was treated as a report")
	}
}

type brokenOutput struct{ short bool }

func (w brokenOutput) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("PRIVATE_OUTPUT_PATH")
}

func FuzzQueryReportDecode(f *testing.F) {
	r, e := matchingInputs(f)
	f.Add(encode(f, r), encode(f, e))
	f.Add([]byte(`{"schema_version":1,"schema_version":1}`), []byte(`null`))
	f.Fuzz(func(t *testing.T, raw, expected []byte) {
		if len(raw) > maxReportBytes || len(expected) > maxExpectationsBytes {
			t.Skip()
		}
		var report queryReport
		var targets expectations
		if decodeExact(raw, &report) && decodeExact(expected, &targets) && validReport(report) && validExpectations(targets) {
			category := matchReport(report, targets)
			if category == "" && len(report.Results) != len(targets.Targets) {
				t.Fatal("partial batch matched")
			}
		}
	})
}
