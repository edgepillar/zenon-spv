// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func batchContextCheckpoint(t *testing.T, f batchContextCLIInputs, count int) (string, []byte) {
	t.Helper()
	c, err := decodeExperimentalContextCLIConfig(experimentalCLIJSON(t, f.config))
	if err != nil {
		t.Fatal(err)
	}
	var pin chain.Hash
	if pin.UnmarshalText([]byte(f.headerPin)) != nil {
		t.Fatal("fixture header pin")
	}
	state, err := verify.NewExperimentalV3State(c.HeaderProfile, c.HeaderPolicy, c.Schedule, pin)
	if err != nil {
		t.Fatal(err)
	}
	rows := f.bundle["momentums"].([]json.RawMessage)
	headers := make([]chain.CandidateV3Header, 0, count)
	for _, row := range rows[:count] {
		h, err := fetch.DecodeCandidateV3Momentum(row)
		if err != nil {
			t.Fatal(err)
		}
		headers = append(headers, h.Header)
	}
	if count > 0 {
		result, next := state.Extend(headers)
		if result.Outcome != verify.OutcomeAccept {
			t.Fatal(result)
		}
		state = next
	}
	path := filepath.Join(filepath.Dir(f.configPath), "PRIVATE_CHECKPOINT.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, raw
}

func batchContextCheckpointArgs(f batchContextCLIInputs, path string, raw []byte) []string {
	digest := sha256.Sum256(raw)
	args := f.args()
	selected := append([]string(nil), args[:len(args)-1]...)
	return append(selected, "--trusted-state", path, "--expect-state-sha256", hex.EncodeToString(digest[:]), f.bundlePath)
}

func TestExperimentalBatchContextCheckpointCLI(t *testing.T) {
	for _, count := range []int{2, 4} {
		name := "successors"
		if count == 4 {
			name = "proof_only"
		}
		t.Run(name, func(t *testing.T) {
			f := newBatchContextCLIInputs(t)
			baseline := batchContextCLIReport(t, experimentalContextQueryCommand, f.args(), 0)
			if baseline.StateInput != nil {
				t.Fatal("default anchor replay changed")
			}
			path, raw := batchContextCheckpoint(t, f, count)
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			f.bundle["momentums"] = f.bundle["momentums"].([]json.RawMessage)[count:]
			f.write(t)
			got := batchContextCLIReport(t, experimentalContextQueryCommand, batchContextCheckpointArgs(f, path, raw), 0)
			if got.StateInput == nil || got.StateInput.Bytes != uint64(len(raw)) || got.StateInput.ProviderHeaders != uint32(4-count) ||
				got.StateInput.Trust != "trusted_local_provenance_required" || got.Result == nil {
				t.Fatal("checkpoint source or reduced provider range omitted")
			}
			found := false
			for _, trust := range got.Result.HeaderTrust {
				found = found || trust == verify.TrustPersistedState
			}
			if !found || count == 4 && got.Headers != nil || count == 2 && (got.Headers == nil || got.Headers.Outcome != "ACCEPT") {
				t.Fatal("checkpoint/extension provenance changed")
			}
			got.Result.HeaderTrust = baseline.Result.HeaderTrust
			if !reflect.DeepEqual(got.Result, baseline.Result) {
				t.Fatal("resumed query changed proven rows or identity")
			}
			after, err := os.Stat(path)
			actual, readErr := os.ReadFile(path)
			if err != nil || readErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() ||
				!before.ModTime().Equal(after.ModTime()) || !bytes.Equal(actual, raw) {
				t.Fatal("read-only query rewrote its trusted checkpoint", err, readErr)
			}
		})
	}
}

func TestExperimentalBatchContextCheckpointFailures(t *testing.T) {
	for _, name := range []string{"digest", "missing-state", "directory", "oversize", "matching-malformed", "matching-wrong-context", "matching-native-format", "empty-checkpoint", "stale-tip", "old-range", "pruned-height", "unavailable-witness", "provider-checkpoint"} {
		t.Run(name, func(t *testing.T) {
			f := newBatchContextCLIInputs(t)
			count := 4
			switch name {
			case "empty-checkpoint":
				count = 0
			case "stale-tip":
				count = 2
			}
			path, raw := batchContextCheckpoint(t, f, count)
			rows := f.bundle["momentums"].([]json.RawMessage)
			f.bundle["momentums"] = rows[:0]
			args := batchContextCheckpointArgs(f, path, raw)
			want := 70
			switch name {
			case "digest":
				args[len(args)-2] = strings.Repeat("1", 64)
				// A digest refusal must happen before any provider-file read.
				args[len(args)-1] = filepath.Join(filepath.Dir(path), "PRIVATE_MISSING_PROVIDER")
				want = 1
			case "missing-state":
				args[len(args)-4] = filepath.Join(filepath.Dir(path), "PRIVATE_MISSING_STATE")
			case "directory":
				args[len(args)-4] = filepath.Dir(path)
			case "oversize":
				if err := os.WriteFile(path, bytes.Repeat([]byte{' '}, int(verify.MaxExperimentalV3StateBytes)+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "matching-malformed", "matching-wrong-context", "matching-native-format":
				bad := []byte("{")
				if name != "matching-malformed" {
					var fields map[string]any
					if json.Unmarshal(raw, &fields) != nil {
						t.Fatal("checkpoint fields")
					}
					if name == "matching-wrong-context" {
						fields["context"] = strings.Repeat("1", 64)
					} else {
						fields["version"] = 3
					}
					bad = experimentalCLIJSON(t, fields)
				}
				if err := os.WriteFile(path, bad, 0600); err != nil {
					t.Fatal(err)
				}
				args = batchContextCheckpointArgs(f, path, bad)
			case "stale-tip":
				want = 1
			case "old-range":
				f.bundle["momentums"] = rows
				want = 1
			case "pruned-height":
				h, err := fetch.DecodeCandidateV3Momentum(rows[1])
				if err != nil {
					t.Fatal(err)
				}
				f.request.Height, f.request.HeaderHash = 88, h.Header.Header.HeaderHash
				want = 2
			case "unavailable-witness":
				f.bundle["witnesses"].(map[string]any)["domain_config"] = nil
				want = 2
			case "provider-checkpoint":
				f.bundle["trusted_state"] = json.RawMessage(raw)
			}
			f.write(t)
			report := batchContextCLIReport(t, experimentalContextQueryCommand, args, want)
			if name == "digest" && (report.Error == nil || report.Error.Stage != "state_input" || report.Error.Category != "digest_mismatch") {
				t.Fatal("digest check was bypassed")
			}
		})
	}
	// Empty headers retain their original refusal without trusted provenance.
	f := newBatchContextCLIInputs(t)
	f.bundle["momentums"] = []json.RawMessage{}
	f.write(t)
	report := batchContextCLIReport(t, experimentalContextQueryCommand, f.args(), 2)
	if report.StateInput != nil || report.Error == nil || report.Error.Stage != "headers" {
		t.Fatal("proof-only provider created header authority")
	}
}

func TestExperimentalBatchContextCheckpointArguments(t *testing.T) {
	f := newBatchContextCLIInputs(t)
	missing := filepath.Join(filepath.Dir(f.configPath), "PRIVATE_MISSING")
	base := []string{"--config", missing, "--request", missing, "--expect-header-context", f.headerPin, "--expect-query-context", f.queryPin}
	for _, extra := range [][]string{
		{"--trusted-state", missing}, {"--expect-state-sha256", strings.Repeat("1", 64)},
		{"--trusted-state", ""}, {"--trusted-state", "", "--expect-state-sha256", strings.Repeat("1", 64)},
		{"--trusted-state", missing, "--expect-state-sha256", ""},
		{"--trusted-state", missing, "--expect-state-sha256", strings.Repeat("0", 64)},
		{"--trusted-state", missing, "--expect-state-sha256", "PRIVATE_BAD"},
		{"--trusted-state", missing, "--trusted-state", missing, "--expect-state-sha256", strings.Repeat("1", 64)},
		{"--trusted-state", missing, "--expect-state-sha256", strings.Repeat("1", 64), "--expect-state-sha256", strings.Repeat("1", 64)},
	} {
		args := append(append(append([]string(nil), base...), extra...), missing)
		batchContextCLIReport(t, experimentalContextQueryCommand, args, 64)
	}
}
