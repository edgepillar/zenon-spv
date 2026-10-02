package conformance_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Expectations come from the pinned node corpus and explicitly selected local
// settings, never from the candidate report. Mutations test diagnostic parsing
// and matching only; they do not become new cryptographic or network evidence.
func TestCompiledQueryReportConsumer(t *testing.T) {
	bins := buildQueryCLIs(t, "zenon-spv", "consume-query-report")
	c := loadNodeAccountCorpus(t, "contract-batches.json")
	seed := proof.HeaderBundle{Version: proof.WireVersion, ChainID: c.Chain.Anchor.ChainID, ClaimedGenesis: c.Chain.Anchor.HeaderHash}
	for _, v := range c.Chain.Vectors {
		seed.Headers = append(seed.Headers, v.Header)
		for _, target := range v.Content {
			seed.Commitments = append(seed.Commitments, proof.CommitmentEvidence{Height: v.Header.Height, Target: target,
				Flat: &proof.FlatContentEvidence{SortedHeaders: v.Content}})
		}
	}
	for _, segment := range c.Segments {
		s := proof.AccountSegment{Address: segment.Address}
		for _, v := range segment.Vectors {
			s.Blocks = append(s.Blocks, v.Block)
		}
		seed.Segments = append(seed.Segments, s)
	}
	if len(seed.Commitments) != 5 || len(seed.Segments) != 1 || len(seed.Segments[0].Blocks) != 5 {
		t.Fatal("incomplete direct-inclusion corpus")
	}
	dir := t.TempDir()
	anchor := writeCLIJSON(t, dir, "anchor.json", c.Chain.Anchor)
	seedPath := writeCLIJSON(t, dir, "seed.json", seed)
	statePath := filepath.Join(dir, "trusted-state.json")
	common := []string{"--json", "--genesis-config", anchor, "--state", statePath}
	checkProcessReport(t, runQueryCLI(t, bins["zenon-spv"], append([]string{"verify-headers"}, append(slices.Clone(common), seedPath)...)...), 0, "ACCEPT")
	unchanged := protectCLIState(t, statePath)
	t.Cleanup(unchanged)
	// The node corpus independently pins this frontier hash, including children.
	tip := seed.Headers[len(seed.Headers)-1]
	seed.Headers = nil
	candidate := writeCLIJSON(t, dir, "proof-only.json", seed)
	initial, err := verify.NewVerifiedState(c.Chain.Anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	context, err := initial.VerificationContext()
	if err != nil || context.Fingerprint == nil {
		t.Fatal("explicit settings have no fingerprint")
	}
	pin := hex.EncodeToString(context.Fingerprint[:])
	query := append(slices.Clone(common), "--retained-only", "--expect-context", pin)
	makeExpected := func(command, fingerprint string) map[string]any {
		targets := make([]any, len(seed.Commitments))
		for i, commitment := range seed.Commitments {
			ref := map[string]any{"scope": "commitment", "index": uint64(i), "momentum_height": commitment.Height, "account_header": commitment.Target}
			if command == "verify-segment" {
				ref = map[string]any{"scope": "segment", "index": uint64(0), "block_index": uint64(i), "account_header": commitment.Target}
			}
			targets[i] = ref
		}
		return map[string]any{"schema_version": 1, "command": command, "context_fingerprint": fingerprint,
			"verification_tip": map[string]any{"hash": tip.HeaderHash, "height": tip.Height}, "targets": targets,
			"required_guarantees":       []string{"CONTENT_INCLUSION"},
			"allowed_trust_assumptions": []string{"TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_RETAINED_WINDOW_DEPTH"}}
	}
	consume := func(t *testing.T, report []byte, expected any, status, want int) {
		t.Helper()
		reportPath := filepath.Join(dir, "query.json")
		if err := os.WriteFile(reportPath, report, 0o600); err != nil {
			t.Fatal(err)
		}
		expectedPath := writeCLIJSON(t, dir, "expectations.json", expected)
		result := runQueryCLI(t, bins["consume-query-report"], "--report", reportPath, "--expectations", expectedPath, "--verifier-exit-code", strconv.Itoa(status))
		count, state := 0, "not_matched"
		if want == 0 {
			count, state = 5, "matched"
		}
		var summary struct {
			Version  int     `json:"schema_version"`
			Status   string  `json:"status"`
			Category *string `json:"category"`
			Count    int     `json:"checked_targets"`
		}
		if result.code != want || len(result.stderr) != 0 || json.Unmarshal(result.stdout, &summary) != nil || summary.Version != 1 ||
			summary.Status != state || summary.Count != count || (summary.Category == nil) != (want == 0) {
			t.Fatal("consumer completion disagrees with the expected fixed summary")
		}
		for _, private := range []string{dir, "PRIVATE", pin, hex.EncodeToString(seed.Commitments[0].Target.Address[:])} {
			if bytes.Contains(result.stdout, []byte(private)) {
				t.Fatal("consumer reproduced private report material")
			}
		}
		if len(losslessObject(t, result.stdout)) != 4 {
			t.Fatal("summary acquired unintended fields")
		}
		unchanged()
	}
	var segment queryCLIResult
	for _, command := range []string{"verify-commitment", "verify-segment"} {
		t.Run(command, func(t *testing.T) {
			result := runQueryCLI(t, bins["zenon-spv"], append([]string{command}, append(slices.Clone(query), candidate)...)...)
			assertProcessInclusions(t, checkProcessReport(t, result, 0, "ACCEPT"), seed)
			consume(t, result.stdout, makeExpected(command, pin), result.code, 0)
			if command == "verify-segment" {
				segment = result
			}
		})
	}
	if segment.code != 0 || len(segment.stdout) == 0 {
		t.Fatal("baseline query did not complete")
	}
	t.Run("schema two explicit retention", func(t *testing.T) {
		policy := verify.DefaultPolicy()
		policy.RetainHeaders = 16
		selected, err := verify.NewVerifiedState(c.Chain.Anchor, verify.VerifyOptions{Policy: policy})
		if err != nil {
			t.Fatal(err)
		}
		ctx, err := selected.VerificationContext()
		if err != nil || ctx.Fingerprint == nil {
			t.Fatal("explicit retention has no fingerprint")
		}
		fp := hex.EncodeToString(ctx.Fingerprint[:])
		args := []string{"verify-segment", "--json", "--retained-only", "--genesis-config", anchor, "--state", statePath, "--retain-headers", "16", "--expect-context", fp, candidate}
		result := runQueryCLI(t, bins["zenon-spv"], args...)
		checkProcessReport(t, result, 0, "ACCEPT")
		consume(t, result.stdout, makeExpected("verify-segment", fp), result.code, 0)
	})
	t.Run("result ordering does not change identities", func(t *testing.T) {
		r := losslessObject(t, segment.stdout)
		slices.Reverse(r["results"].([]any))
		consume(t, marshalCLIValue(t, r), makeExpected("verify-segment", pin), 0, 0)
	})
	t.Run("actual failed process overrides complete ACCEPT", func(t *testing.T) {
		bad := append([]string{"verify-segment"}, append(slices.Clone(common), "--retained-only", "--expect-context", strings.Repeat("1", 64), candidate)...)
		failed := runQueryCLI(t, bins["zenon-spv"], bad...)
		if failed.code != 70 {
			t.Fatal("expected a real context-pin failure")
		}
		consume(t, segment.stdout, makeExpected("verify-segment", pin), failed.code, 2)
	})
	for _, tc := range []struct {
		name   string
		report func(map[string]any)
		expect func(map[string]any)
		raw    func(string) string
	}{
		{name: "wrong target", report: func(r map[string]any) { resultAccount(r)["height"] = json.Number("9007199254740993") }},
		{name: "integer rounding cannot match", report: func(r map[string]any) { resultAccount(r)["height"] = json.Number("9007199254740993") }, expect: func(e map[string]any) {
			e["targets"].([]any)[0].(map[string]any)["account_header"] = map[string]any{"address": seed.Commitments[0].Target.Address, "hash": seed.Commitments[0].Target.Hash, "height": json.Number("9007199254740992")}
		}},
		{name: "wrong tip", expect: func(e map[string]any) {
			e["verification_tip"] = map[string]any{"hash": tip.HeaderHash, "height": tip.Height - 1}
		}},
		{name: "wrong context", expect: func(e map[string]any) { e["context_fingerprint"] = strings.Repeat("2", 64) }},
		{name: "changed context with old fingerprint", report: func(r map[string]any) {
			r["verification_context"].(map[string]any)["policy"].(map[string]any)["w"] = json.Number("99")
		}},
		{name: "missing result", report: func(r map[string]any) { r["results"] = r["results"].([]any)[:4] }},
		{name: "extra result", report: func(r map[string]any) {
			row := losslessObject(t, marshalCLIValue(t, firstResult(r)))
			row["reference"].(map[string]any)["block_index"] = 6
			r["results"] = append(r["results"].([]any), row)
		}},
		{name: "duplicate result", report: func(r map[string]any) { r["results"] = append(r["results"].([]any), firstResult(r)) }},
		{name: "missing index zero", report: func(r map[string]any) { delete(firstResult(r)["reference"].(map[string]any), "index") }},
		{name: "null guarantees", report: func(r map[string]any) { firstResult(r)["proven"] = nil }},
		{name: "inclusion only unproven", report: func(r map[string]any) {
			firstResult(r)["proven"] = []any{}
			firstResult(r)["not_proven"] = append(firstResult(r)["not_proven"].([]any), "CONTENT_INCLUSION")
		}},
		{name: "required signature missing", expect: func(e map[string]any) {
			e["required_guarantees"] = []string{"CONTENT_INCLUSION", "SIGNATURE_AUTHENTICITY"}
		}},
		{name: "state values unsupported", expect: func(e map[string]any) {
			e["required_guarantees"] = []string{"CONTENT_INCLUSION", "STATE_VALUE_INCLUSION"}
		}},
		{name: "canonicality unsupported", expect: func(e map[string]any) { e["required_guarantees"] = []string{"CONTENT_INCLUSION", "CANONICALITY"} }},
		{name: "unallowed state trust", report: func(r map[string]any) { r["state_trust"] = append(r["state_trust"].([]any), "TRUST_RPC_QUORUM") }},
		{name: "unallowed row trust", report: func(r map[string]any) {
			firstResult(r)["trust_assumptions"] = append(firstResult(r)["trust_assumptions"].([]any), "TRUST_RPC_QUORUM")
		}},
		{name: "unknown report field", report: func(r map[string]any) { r["PRIVATE_FIELD"] = "PRIVATE_VALUE" }},
		{name: "case alias", report: func(r map[string]any) { r["Exit_Code"] = r["exit_code"]; delete(r, "exit_code") }},
		{name: "duplicate key", raw: func(r string) string { return strings.Replace(r, `"exit_code":0`, `"exit_code":0,"exit_code":0`, 1) }},
		{name: "uint64 overflow", report: func(r map[string]any) { resultAccount(r)["height"] = json.Number("18446744073709551616") }},
		{name: "floating integer", raw: func(r string) string { return strings.Replace(r, `"exit_code":0`, `"exit_code":0.0`, 1) }},
		{name: "truncated JSON", raw: func(r string) string { return r[:len(r)-1] }},
		{name: "extra JSON value", raw: func(r string) string { return r + `{}` }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := losslessObject(t, segment.stdout)
			e := makeExpected("verify-segment", pin)
			if tc.report != nil {
				tc.report(r)
			}
			if tc.expect != nil {
				tc.expect(e)
			}
			raw := marshalCLIValue(t, r)
			if tc.raw != nil {
				mutated := tc.raw(string(raw))
				if mutated == string(raw) {
					t.Fatal("mutation was not applied")
				}
				raw = []byte(mutated)
			}
			consume(t, raw, e, 0, 2)
		})
	}
}

func losslessObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func marshalCLIValue(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func firstResult(r map[string]any) map[string]any { return r["results"].([]any)[0].(map[string]any) }
func resultAccount(r map[string]any) map[string]any {
	return firstResult(r)["reference"].(map[string]any)["account_header"].(map[string]any)
}
