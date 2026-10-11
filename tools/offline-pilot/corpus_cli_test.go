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
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// Stable nonregular/oversized selected JSON files are refused by the earlier
// source preflight. These controls reach corpus capture with missing members or
// an empty directory; complete raw hashes are observed in an incomplete pilot.
func TestCompiledPilotCorpusCapture(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("native corpus capture requires Go")
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
		t.Fatal("cannot build ordinary corpus capture executable")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("cannot pin ordinary corpus executable")
	}
	pin := sha256.Sum256(raw)
	type control struct {
		Name          string `json:"name"`
		Exit          int    `json:"exit_code"`
		Stage         string `json:"stage"`
		Captured      int    `json:"corpus_records"`
		HashMatch     bool   `json:"raw_hashes_and_order_matched"`
		ExportCreated bool   `json:"candidate_directory_created"`
	}
	var records []control
	for selected := range len(corpusPaths) + 2 {
		name := "complete_corpus_incomplete_pilot"
		if selected < len(corpusPaths) {
			name = "missing_member_" + strconv.Itoa(selected+1)
		} else if selected == len(corpusPaths) {
			name = "directory_last_member"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"cmd", "internal", "tools"} {
				if os.Mkdir(filepath.Join(root, dir), 0700) != nil {
					t.Fatal("cannot prepare corpus source roots")
				}
			}
			if os.WriteFile(filepath.Join(root, "go.mod"), []byte("module "+modulePath+"\n"), 0600) != nil || os.WriteFile(filepath.Join(root, "go.sum"), nil, 0600) != nil {
				t.Fatal("cannot prepare corpus source module")
			}
			var expected []corpusRecord
			for i, path := range corpusPaths {
				if i == selected {
					continue
				}
				pathOnDisk := filepath.Join(root, filepath.FromSlash(path))
				if os.MkdirAll(filepath.Dir(pathOnDisk), 0700) != nil {
					t.Fatal("cannot prepare corpus parents")
				}
				if selected == len(corpusPaths) && i == len(corpusPaths)-1 {
					if os.Mkdir(pathOnDisk, 0700) != nil {
						t.Fatal("cannot prepare non-file corpus member")
					}
					continue
				}
				value := []byte("{\"fixture\":" + strconv.Itoa(i) + "}\n")
				if os.WriteFile(pathOnDisk, value, 0600) != nil {
					t.Fatal("cannot prepare fixed corpus member")
				}
				digest := sha256.Sum256(value)
				expected = append(expected, corpusRecord{path, hex.EncodeToString(digest[:])})
			}
			export := filepath.Join(root, "PRIVATE_EXPORT")
			args := []string{"--timeout", "15s"}
			complete := selected == len(corpusPaths)+1
			if !complete {
				args = append(args, "--export-binaries", export)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, args...)
			cmd.Dir, cmd.Env, cmd.WaitDelay = root, pilotEnvironment(goTool), time.Second
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			if ctx.Err() != nil || err == nil || cmd.ProcessState == nil {
				t.Fatal("ordinary corpus control failed its exit contract")
			}
			record := control{Name: name, Exit: cmd.ProcessState.ExitCode(), Stage: "corpus"}
			if complete {
				var report pilotReport
				if record.Exit != 1 || stderr.Len() != 0 || json.Unmarshal(stdout.Bytes(), &report) != nil ||
					(report.Status != "failed" && report.Status != "incomplete") || !report.InputsUnchanged || !reflect.DeepEqual(report.Corpus, expected) {
					t.Fatal("incomplete ordinary pilot did not preserve all seven raw corpus hashes")
				}
				record.Stage, record.Captured, record.HashMatch = "test_process", len(report.Corpus), true
			} else if record.Exit != 70 || stdout.Len() != 0 || stderr.String() != "offline-pilot: corpus setup failed\n" {
				t.Fatal("ordinary corpus refusal disclosed paths or yielded partial evidence")
			}
			if _, err := os.Lstat(export); !os.IsNotExist(err) {
				t.Fatal("corpus control created a candidate directory")
			}
			records = append(records, record)
		})
	}
	if len(records) != 9 {
		t.Fatal("incomplete ordinary corpus control inventory")
	}
	record, err := json.Marshal(struct {
		Version      int       `json:"schema_version"`
		SHA256       string    `json:"ordinary_binary_sha256"`
		OS           string    `json:"os"`
		Architecture string    `json:"architecture"`
		Controls     []control `json:"controls"`
	}{1, hex.EncodeToString(pin[:]), runtime.GOOS, runtime.GOARCH, records})
	if err != nil {
		t.Fatal("cannot encode ordinary corpus controls")
	}
	t.Logf("offline-pilot-corpus-compiled-controls %s", record)
}
