// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func batchContextExportReport(t *testing.T, args []string, want int) ([]byte, experimentalContextCLIReport) {
	t.Helper()
	var checkpoint, diagnostics bytes.Buffer
	code := runExperimentalBatchContext(experimentalContextExportCommand, args, &checkpoint, &diagnostics)
	var report experimentalContextCLIReport
	if code != want || json.Unmarshal(diagnostics.Bytes(), &report) != nil || report.ExitCode != code ||
		report.Command != experimentalContextExportCommand || report.RPCRequests != 0 || report.ProductionStateValueGuarantee {
		t.Fatal("checkpoint command scope", code, diagnostics.String())
	}
	if strings.Contains(checkpoint.String(), "PRIVATE") || strings.Contains(diagnostics.String(), "PRIVATE") {
		t.Fatal("private provenance or diagnostics exposed")
	}
	if code != 0 {
		if checkpoint.Len() != 0 || report.StateOutput != nil || report.Result != nil || report.Persistence != "checkpoint_not_exported" {
			t.Fatal("refused query emitted a checkpoint or consumer row")
		}
		return nil, report
	}
	digest := sha256.Sum256(checkpoint.Bytes())
	if report.Status != "matched" || report.Result == nil || report.StateOutput == nil || !report.StateOutput.Complete ||
		report.StateOutput.SHA256 != hex.EncodeToString(digest[:]) || report.StateOutput.Bytes != uint64(checkpoint.Len()) ||
		report.StateOutput.Trust != "trusted_local_provenance_required" || !report.StateOutput.ProvenanceLabelRemoved || report.Persistence != "checkpoint_streamed" {
		t.Fatal("checkpoint completion receipt does not identify the emitted bytes")
	}
	return checkpoint.Bytes(), report
}

func TestExperimentalBatchContextCheckpointExportCLI(t *testing.T) {
	f := newBatchContextCLIInputs(t)
	f.config["header_profile"].(map[string]any)["source"] = "PRIVATE operator provenance"
	f.write(t)
	baseline := batchContextCLIReport(t, experimentalContextQueryCommand, f.args(), 0)
	type snapshot struct {
		info os.FileInfo
		raw  []byte
	}
	inputs := map[string]snapshot{}
	for _, path := range []string{f.configPath, f.requestPath, f.bundlePath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		inputs[path] = snapshot{info, raw}
	}
	raw, exported := batchContextExportReport(t, f.args(), 0)
	if !reflect.DeepEqual(exported.Result, baseline.Result) || exported.StateInput != nil || exported.Headers == nil || exported.Headers.Outcome != "ACCEPT" {
		t.Fatal("export changed the original consumer decision")
	}
	for path, before := range inputs {
		info, err := os.Stat(path)
		actual, readErr := os.ReadFile(path)
		if err != nil || readErr != nil || !os.SameFile(before.info, info) || before.info.Mode() != info.Mode() ||
			!before.info.ModTime().Equal(info.ModTime()) || !bytes.Equal(before.raw, actual) {
			t.Fatal("export modified an input", err, readErr)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(f.configPath))
	if err != nil || len(entries) != 3 {
		t.Fatal("export created output files", err)
	}
	// The caller selects a new trusted local path and retains successful output.
	// The command itself creates no file or expected-digest authority.
	path := filepath.Join(filepath.Dir(f.configPath), "checkpoint.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f.bundle["momentums"] = []json.RawMessage{}
	f.write(t)
	args := batchContextCheckpointArgs(f, path, raw)
	resumed := batchContextCLIReport(t, experimentalContextQueryCommand, args, 0)
	if resumed.Headers != nil || resumed.StateInput == nil || resumed.StateInput.ProviderHeaders != 0 || resumed.Result == nil {
		t.Fatal("the exported checkpoint cannot serve the existing proof-only query")
	}
	resumed.Result.HeaderTrust = baseline.Result.HeaderTrust
	if !reflect.DeepEqual(resumed.Result, baseline.Result) {
		t.Fatal("proof-only consumption changed the typed result")
	}
	again, repeated := batchContextExportReport(t, args, 0)
	if !bytes.Equal(again, raw) || repeated.Headers != nil || repeated.StateInput == nil || repeated.StateInput.ProviderHeaders != 0 {
		t.Fatal("trusted checkpoint re-export changed bytes or fabricated header extension")
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, raw) {
		t.Fatal("checkpoint consumer rewrote the selected local file", err)
	}
}

func TestExperimentalBatchContextCheckpointExportRefusals(t *testing.T) {
	for _, name := range []string{"header-pin", "query-pin", "request", "root", "unavailable", "proven-absence", "unknown-flag"} {
		t.Run(name, func(t *testing.T) {
			f := newBatchContextCLIInputs(t)
			args, want := f.args(), 70
			switch name {
			case "header-pin":
				args[5] = strings.Repeat("1", 64)
			case "query-pin":
				args[7] = strings.Repeat("1", 64)
			case "request":
				f.request.Context[0] ^= 1
			case "root":
				f.bundle["witnesses"].(map[string]any)["batch_entry"].(map[string]any)["root"] = strings.Repeat("1", 64)
				want = 1
			case "unavailable":
				f.bundle["witnesses"].(map[string]any)["batch_entry"] = nil
				want = 2
			case "proven-absence":
				f.request.BatchID = 1
				row := f.bundle["witnesses"].(map[string]any)["batch_entry"].(map[string]any)
				row["proof"], row["value"] = f.absent, nil
				want = 2
			case "unknown-flag":
				args, want = []string{"--PRIVATE-flag"}, 64
			}
			f.write(t)
			baseline := batchContextCLIReport(t, experimentalContextQueryCommand, args, want)
			_, exported := batchContextExportReport(t, args, want)
			if !reflect.DeepEqual(exported.Error, baseline.Error) || exported.Status != baseline.Status {
				t.Fatal("export bypassed the existing query refusal")
			}
		})
	}
}

type experimentalContextExportWriteFunc func([]byte) (int, error)

func (f experimentalContextExportWriteFunc) Write(raw []byte) (int, error) { return f(raw) }

func TestExperimentalBatchContextCheckpointExportOutputFailures(t *testing.T) {
	f := newBatchContextCLIInputs(t)
	privateFailure := errors.New("PRIVATE output failure")
	for _, test := range []struct {
		name  string
		write func(*bytes.Buffer, []byte) (int, error)
	}{
		{"short", func(out *bytes.Buffer, raw []byte) (int, error) { return out.Write(raw[:len(raw)/2]) }},
		{"last-byte-short", func(out *bytes.Buffer, raw []byte) (int, error) { return out.Write(raw[:len(raw)-1]) }},
		{"failed", func(*bytes.Buffer, []byte) (int, error) { return 0, privateFailure }},
		{"partial-failed", func(out *bytes.Buffer, raw []byte) (int, error) {
			n, _ := out.Write(raw[:16])
			return n, privateFailure
		}},
		{"negative-count", func(*bytes.Buffer, []byte) (int, error) { return -1, nil }},
		{"oversized-count", func(_ *bytes.Buffer, raw []byte) (int, error) { return len(raw) + 1, nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			writer := experimentalContextExportWriteFunc(func(raw []byte) (int, error) { return test.write(&output, raw) })
			code := runExperimentalBatchContext(experimentalContextExportCommand, f.args(), writer, &diagnostics)
			var report experimentalContextCLIReport
			if code != 70 || json.Unmarshal(diagnostics.Bytes(), &report) != nil || report.ExitCode != 70 ||
				report.Error == nil || report.Error.Stage != "checkpoint_output" || report.StateOutput != nil || report.Result != nil ||
				report.Persistence != "checkpoint_output_incomplete" || strings.Contains(diagnostics.String(), "PRIVATE") {
				t.Fatal("incomplete output became a successful checkpoint", code, diagnostics.String())
			}
		})
	}
	t.Run("completion-receipt-failed", func(t *testing.T) {
		var output bytes.Buffer
		failed := experimentalContextExportWriteFunc(func([]byte) (int, error) { return 0, privateFailure })
		if code := runExperimentalBatchContext(experimentalContextExportCommand, f.args(), &output, failed); code != 70 || !json.Valid(output.Bytes()) {
			t.Fatal("receipt failure was hidden or preceding checkpoint bytes were fabricated", code)
		}
	})
}

// Reuse the existing compiled workflow's binary instead of adding another build.
func testCompiledExperimentalContextCheckpoint(t *testing.T, ctx context.Context, binary string) {
	t.Helper()
	f := newBatchContextCLIInputs(t)
	invoke := func(args []string, checkpoint bool) ([]byte, experimentalContextCLIReport) {
		t.Helper()
		cmd := exec.CommandContext(ctx, binary, args...)
		var output, diagnostics bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &diagnostics
		if err := cmd.Run(); err != nil {
			t.Fatal("compiled context checkpoint workflow", err, diagnostics.String())
		}
		raw := output.Bytes()
		if checkpoint {
			raw = diagnostics.Bytes()
		} else if diagnostics.Len() != 0 {
			t.Fatal("read-only query diagnostics changed")
		}
		var report experimentalContextCLIReport
		if json.Unmarshal(raw, &report) != nil || report.ExitCode != 0 || report.Result == nil || report.RPCRequests != 0 || report.ProductionStateValueGuarantee {
			t.Fatal("compiled workflow did not produce the selected consumer result")
		}
		if checkpoint {
			digest := sha256.Sum256(output.Bytes())
			if report.StateOutput == nil || !report.StateOutput.Complete || report.StateOutput.SHA256 != hex.EncodeToString(digest[:]) || report.StateOutput.Bytes != uint64(output.Len()) {
				t.Fatal("compiled checkpoint receipt does not match the stream")
			}
		}
		return output.Bytes(), report
	}
	raw, exported := invoke(append([]string{experimentalContextExportCommand}, f.args()...), true)
	path := filepath.Join(filepath.Dir(f.configPath), "compiled-checkpoint.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f.bundle["momentums"] = []json.RawMessage{}
	f.write(t)
	args := batchContextCheckpointArgs(f, path, raw)
	_, resumed := invoke(append([]string{experimentalContextQueryCommand}, args...), false)
	if resumed.Headers != nil || resumed.StateInput == nil || resumed.StateInput.ProviderHeaders != 0 {
		t.Fatal("compiled proof-only query did not consume the exported checkpoint")
	}
	resumed.Result.HeaderTrust = exported.Result.HeaderTrust
	if !reflect.DeepEqual(resumed.Result, exported.Result) {
		t.Fatal("compiled checkpoint changed the typed consumer result")
	}
	again, repeated := invoke(append([]string{experimentalContextExportCommand}, args...), true)
	if !bytes.Equal(again, raw) || repeated.Headers != nil || repeated.StateInput == nil {
		t.Fatal("compiled checkpoint re-export was not byte stable")
	}
}
