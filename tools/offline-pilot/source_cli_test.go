package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Ordinary builds exercise the complete preflight, before tests or exports.
// Minimal source fixtures deliberately lack the selected conformance corpus.
func TestCompiledPilotSourcePreflight(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("native source preflight requires Go")
	}
	binary := filepath.Join(t.TempDir(), "offline-pilot")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	cmd := exec.CommandContext(ctx, goTool, "build", "-trimpath", "-o", binary, ".")
	cmd.Env = pilotEnvironment(goTool)
	buildErr := cmd.Run()
	cancel()
	if buildErr != nil {
		t.Fatal("cannot build ordinary offline pilot")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("cannot pin ordinary offline pilot")
	}
	pin := sha256.Sum256(raw)
	mod := []byte("module " + modulePath + "\n")
	var records []struct {
		Name     string `json:"name"`
		Bytes    int64  `json:"aggregate_source_bytes"`
		Exit     int    `json:"exit_code"`
		Category string `json:"refusal_stage"`
	}
	for _, selected := range []struct {
		name string
		size int64
	}{
		{"empty_member", 0},
		{"one_MiB_member", 1 << 20},
		{"exact_aggregate_ceiling", maxSourceBytes - int64(len(mod))},
		{"aggregate_overflow", maxSourceBytes - int64(len(mod)) + 1},
	} {
		t.Run(selected.name, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"cmd", "internal", "tools"} {
				if os.Mkdir(filepath.Join(root, name), 0700) != nil {
					t.Fatal("cannot prepare source directories")
				}
			}
			if os.WriteFile(filepath.Join(root, "go.mod"), mod, 0600) != nil || os.WriteFile(filepath.Join(root, "go.sum"), nil, 0600) != nil {
				t.Fatal("cannot prepare module selection")
			}
			member := filepath.Join(root, "internal", "PRIVATE_MEMBER.json")
			file, err := os.OpenFile(member, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal("cannot create selected member")
			}
			resizeErr, closeErr := file.Truncate(selected.size), file.Close()
			if resizeErr != nil || closeErr != nil {
				t.Fatal("cannot finish selected member")
			}
			export := filepath.Join(root, "PRIVATE_EXPORT")
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "--export-binaries", export)
			cmd.Dir, cmd.Env, cmd.WaitDelay = root, pilotEnvironment(goTool), time.Second
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err = cmd.Run()
			if ctx.Err() != nil || err == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 70 || stdout.Len() != 0 {
				t.Fatal("ordinary source preflight failed its exit/output contract")
			}
			stage, expected := "corpus", "offline-pilot: corpus setup failed\n"
			if selected.name == "aggregate_overflow" {
				stage, expected = "source", "offline-pilot: source setup failed; run from the repository root\n"
			}
			if stderr.String() != expected {
				t.Fatal("ordinary preflight disclosed paths or reached an unexpected stage")
			}
			if _, err := os.Lstat(export); !os.IsNotExist(err) {
				t.Fatal("source/corpus refusal created a candidate directory")
			}
			records = append(records, struct {
				Name     string `json:"name"`
				Bytes    int64  `json:"aggregate_source_bytes"`
				Exit     int    `json:"exit_code"`
				Category string `json:"refusal_stage"`
			}{selected.name, selected.size + int64(len(mod)), 70, stage})
		})
	}
	if len(records) != 4 {
		t.Fatal("incomplete compiled source preflight inventory")
	}
	record, err := json.Marshal(struct {
		Version       int    `json:"schema_version"`
		SHA256        string `json:"ordinary_binary_sha256"`
		OS            string `json:"os"`
		Architecture  string `json:"architecture"`
		Controls      any    `json:"controls"`
		ExportCreated bool   `json:"candidate_directory_created"`
	}{1, hex.EncodeToString(pin[:]), runtime.GOOS, runtime.GOARCH, records, false})
	if err != nil {
		t.Fatal("cannot encode compiled preflight inventory")
	}
	t.Logf("offline-pilot-source-compiled-controls %s", record)
}
