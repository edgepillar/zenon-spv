package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Real directories exercise page, entry and depth limits in an ordinary build.
// Accepted source trees deliberately lack the corpus and stop before exports.
func TestCompiledPilotSourceEnumeration(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("native source enumeration requires Go")
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
		t.Fatal("cannot build ordinary enumeration pilot")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("cannot pin ordinary enumeration pilot")
	}
	pin := sha256.Sum256(raw)
	type control struct {
		Name    string `json:"name"`
		Entries int    `json:"child_entries"`
		Depth   int    `json:"deepest_directory_level"`
		Exit    int    `json:"exit_code"`
		Stage   string `json:"refusal_stage"`
		Elapsed int64  `json:"elapsed_ns"`
	}
	prepareRoot := func(t *testing.T) string {
		t.Helper()
		root := t.TempDir()
		for _, name := range []string{"cmd", "internal", "tools"} {
			if os.Mkdir(filepath.Join(root, name), 0700) != nil {
				t.Fatal("cannot prepare source roots")
			}
		}
		if os.WriteFile(filepath.Join(root, "go.mod"), []byte("module "+modulePath+"\n"), 0600) != nil || os.WriteFile(filepath.Join(root, "go.sum"), nil, 0600) != nil {
			t.Fatal("cannot prepare module inputs")
		}
		return root
	}
	// Keep one parent-owned fixture through the three sequential wide cases.
	// Each fresh CLI process sees the actual directory after its next increment.
	wideRoot, wideEntries := prepareRoot(t), 0
	var controls []control
	for _, selected := range []struct {
		name    string
		entries int
		depth   int
		refused bool
	}{
		{"paged_directory", 3*sourceDirectoryPage + 1, 1, false},
		{"exact_entry_ceiling", maxSourceEntries, 1, false},
		{"entry_overflow", maxSourceEntries + 1, 1, true},
		{"exact_depth_ceiling", maxSourceDepth - 1, maxSourceDepth, false},
		{"depth_overflow", maxSourceDepth, maxSourceDepth + 1, true},
		{"non_directory_root", 0, 0, true},
	} {
		t.Run(selected.name, func(t *testing.T) {
			root := wideRoot
			if selected.depth != 1 {
				root = prepareRoot(t)
			}
			if selected.depth == 1 {
				if selected.entries <= wideEntries {
					t.Fatal("wide source controls must grow the same fixture")
				}
				for i := wideEntries; i < selected.entries; i++ {
					name := filepath.Join(root, "internal", fmt.Sprintf("PRIVATE_IGNORED_%05d.txt", i))
					file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
					if err != nil {
						t.Fatal("cannot prepare wide source tree")
					}
					if file.Close() != nil {
						t.Fatal("cannot close wide source member")
					}
				}
				wideEntries = selected.entries
			} else if selected.depth > 1 {
				dir := filepath.Join(root, "internal")
				for depth := 2; depth <= selected.depth; depth++ {
					dir = filepath.Join(dir, "d")
					if os.Mkdir(dir, 0700) != nil {
						t.Fatal("cannot prepare deep source tree")
					}
				}
			} else {
				path := filepath.Join(root, "cmd")
				if os.Remove(path) != nil || os.WriteFile(path, nil, 0600) != nil {
					t.Fatal("cannot prepare non-directory root")
				}
			}
			export := filepath.Join(root, "PRIVATE_EXPORT")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "--export-binaries", export)
			cmd.Dir, cmd.Env, cmd.WaitDelay = root, pilotEnvironment(goTool), time.Second
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			started := time.Now()
			err = cmd.Run()
			elapsed := time.Since(started).Nanoseconds()
			if ctx.Err() != nil || err == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 70 || stdout.Len() != 0 {
				t.Fatal("ordinary enumeration preflight failed its exit/output contract")
			}
			stage, diagnostic := "corpus", "offline-pilot: corpus setup failed\n"
			if selected.refused {
				stage, diagnostic = "source", "offline-pilot: source setup failed; run from the repository root\n"
			}
			if stderr.String() != diagnostic {
				t.Fatal("ordinary enumeration disclosed private paths or reached an unexpected stage")
			}
			if _, err := os.Lstat(export); !os.IsNotExist(err) {
				t.Fatal("enumeration/corpus refusal created a candidate directory")
			}
			controls = append(controls, control{selected.name, selected.entries, selected.depth, 70, stage, elapsed})
		})
	}
	if len(controls) != 6 {
		t.Fatal("incomplete ordinary enumeration inventory")
	}
	if wideEntries != maxSourceEntries+1 {
		t.Fatal("incomplete incremental wide source fixture")
	}
	record, err := json.Marshal(struct {
		Version      int       `json:"schema_version"`
		SHA256       string    `json:"ordinary_binary_sha256"`
		OS           string    `json:"os"`
		Architecture string    `json:"architecture"`
		Controls     []control `json:"controls"`
		Exported     bool      `json:"candidate_directory_created"`
	}{1, hex.EncodeToString(pin[:]), runtime.GOOS, runtime.GOARCH, controls, false})
	if err != nil {
		t.Fatal("cannot encode ordinary enumeration controls")
	}
	t.Logf("offline-pilot-source-enumeration-compiled-controls %s", record)
}
