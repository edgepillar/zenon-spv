package conformance_test

import (
	"bytes"
	"context"
	binaryinfo "debug/buildinfo"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// Exact helper body from 6fa8300ac6fa0df638cfa727abfb641ee9630ca1, with
// only its function name adapted. Keep fresh ordinary builds as the reference.
func individualQueryCLIsReference(t *testing.T, names ...string) map[string]string {
	t.Helper()
	// Register CLI sources and their internal helpers as test inputs. Some
	// helpers are only imported by the commands, not by this test package.
	// Their edits must invalidate a previously cached compiled-workflow pass.
	for _, dir := range []string{"../../cmd/zenon-spv", "../../cmd/fetch-bundle", "../../tools/derive-producer-schedule", "../../tools/derive-checkpoints", "../../tools/verify-mainnet-genesis", "../../tools/consume-query-report", "../../tools/observe-block", "../../internal"} {
		if err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				_, err := os.ReadFile(path)
				return err
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"../../go.mod", "../../go.sum"} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("compiled CLI conformance requires the Go toolchain on PATH")
	}
	binDir := t.TempDir()
	bins := make(map[string]string)
	if len(names) == 0 {
		names = []string{"zenon-spv", "fetch-bundle"}
	}
	for _, name := range names {
		pkg := "./cmd/" + name
		switch name {
		case "derive-producer-schedule", "derive-checkpoints", "verify-mainnet-genesis", "consume-query-report", "observe-block":
			pkg = "./tools/" + name
		}
		path := filepath.Join(binDir, name)
		if runtime.GOOS == "windows" {
			path += ".exe"
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		cmd := exec.CommandContext(ctx, goTool, "build", "-trimpath", "-o", path, pkg)
		cmd.Dir = "../.."
		cmd.Env = append(queryCLIEnvironment(), "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=", "GOENV=off")
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("build %s: %v\n%s", name, err, output)
		}
		digestHex, _, err := candidateBinaryDigest(path)
		if err != nil {
			t.Fatal("cannot hash compiled CLI for its execution record")
		}
		if dir := os.Getenv(candidateExportEnvironment); dir != "" {
			if err := exportCandidateBinary(dir, name, path, digestHex); err != nil {
				t.Fatal("cannot export compiled CLI for the offline candidate")
			}
		}
		record, err := json.Marshal(struct {
			Command string `json:"command"`
			SHA256  string `json:"sha256"`
		}{name, digestHex})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("offline-pilot-binary %s", record)
		bins[name] = path
	}
	return bins
}

var queryCLIBatchNames = []string{
	"zenon-spv", "fetch-bundle", "derive-producer-schedule", "derive-checkpoints",
	"verify-mainnet-genesis", "consume-query-report", "observe-block",
}

func TestQueryCLIBuildPlan(t *testing.T) {
	reversed := slices.Clone(queryCLIBatchNames)
	slices.Reverse(reversed)
	packages := map[string]string{
		"zenon-spv": "./cmd/zenon-spv", "fetch-bundle": "./cmd/fetch-bundle",
		"derive-producer-schedule": "./tools/derive-producer-schedule",
		"derive-checkpoints":       "./tools/derive-checkpoints",
		"verify-mainnet-genesis":   "./tools/verify-mainnet-genesis",
		"consume-query-report":     "./tools/consume-query-report", "observe-block": "./tools/observe-block",
	}
	cases := []struct {
		name  string
		names []string
	}{
		{"default", []string{"zenon-spv", "fetch-bundle"}},
		{"all", queryCLIBatchNames}, {"reversed", reversed}, {"single", []string{"observe-block"}},
		{"mixed", []string{"fetch-bundle", "derive-producer-schedule"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			names := slices.Clone(tc.names)
			dir := filepath.Join(t.TempDir(), "private output")
			args := queryCLIBuildArguments(dir, names)
			expected := []string{"build", "-p", "1", "-trimpath", "-o", dir + string(os.PathSeparator)}
			for _, name := range tc.names {
				expected = append(expected, packages[name])
			}
			if !slices.Equal(args, expected) || !slices.Equal(names, tc.names) {
				t.Fatal("ordinary build flags, bounded concurrency, path framing or selected order changed")
			}
			for _, flag := range []string{"-race", "-cover", "-work"} {
				if slices.Contains(args, flag) {
					t.Fatal("test-parent instrumentation or retained compiler scratch reached an ordinary build")
				}
			}
		})
	}
	t.Log(`query-cli-build-plan {"schema_version":1,"cases":5,"maximum_commands":7,"build_parallelism":1,"ordinary_builds":true}`)
}

type queryCLIBatchBinary struct {
	Command string `json:"command"`
	SHA256  string `json:"sha256"`
	Bytes   int64  `json:"bytes"`
}

func TestQueryCLIBuildBatch(t *testing.T) {
	// Existing candidate evidence is a separate file set. Repeated builds must
	// compare it without replacement, including after mutation of a private output.
	exports := t.TempDir()
	t.Setenv(candidateExportEnvironment, exports)
	started := time.Now()
	reference := individualQueryCLIsReference(t, queryCLIBatchNames...)
	referenceElapsed := time.Since(started).Nanoseconds()
	exportInfo := make(map[string]os.FileInfo)
	records := make([]queryCLIBatchBinary, 0, len(queryCLIBatchNames))
	for _, name := range queryCLIBatchNames {
		digest, size, err := candidateBinaryDigest(reference[name])
		if err != nil {
			t.Fatal("cannot hash individual reference")
		}
		records = append(records, queryCLIBatchBinary{name, digest, size})
		info, err := os.Stat(filepath.Join(exports, filepath.Base(reference[name])))
		if err != nil {
			t.Fatal("cannot stat original candidate export")
		}
		exportInfo[name] = info
	}
	started = time.Now()
	batch := buildQueryCLIs(t, queryCLIBatchNames...)
	batchElapsed := time.Since(started).Nanoseconds()
	for _, record := range records {
		name := record.Command
		first, err := os.ReadFile(reference[name])
		if err != nil {
			t.Fatal("cannot read individual reference")
		}
		second, err := os.ReadFile(batch[name])
		if err != nil || !bytes.Equal(first, second) {
			t.Fatal("grouped build changed complete executable bytes", name)
		}
		before, err := os.Stat(reference[name])
		if err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(batch[name])
		if err != nil || os.SameFile(before, after) {
			t.Fatal("grouped output aliases an individual output")
		}
		embedded, err := binaryinfo.ReadFile(batch[name])
		if err != nil {
			t.Fatal("ordinary executable has no build identity")
		}
		settings := map[string]string{}
		for _, setting := range embedded.Settings {
			settings[setting.Key] = setting.Value
		}
		if settings["-trimpath"] != "true" || settings["-race"] == "true" || settings["GOOS"] != runtime.GOOS || settings["GOARCH"] != runtime.GOARCH {
			t.Fatal("grouped build changed instrumentation or native target")
		}
	}
	chosen := queryCLIBatchNames[0]
	file, err := os.OpenFile(batch[chosen], os.O_RDWR, 0)
	if err != nil {
		t.Fatal("cannot open private output for independence control")
	}
	var first [1]byte
	if _, err := file.ReadAt(first[:], 0); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	first[0] ^= 1
	_, writeErr := file.WriteAt(first[:], 0)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("cannot mutate newly built private output")
	}
	fresh := buildQueryCLIs(t, chosen)[chosen]
	firstInfo, err := os.Stat(batch[chosen])
	if err != nil {
		t.Fatal(err)
	}
	freshInfo, err := os.Stat(fresh)
	if err != nil || os.SameFile(firstInfo, freshInfo) || fresh == batch[chosen] {
		t.Fatal("a later test group reused the mutated output")
	}
	for _, record := range records {
		digest, size, err := candidateBinaryDigest(reference[record.Command])
		if err != nil || digest != record.SHA256 || size != record.Bytes {
			t.Fatal("private mutation changed the reference")
		}
		destination := filepath.Join(exports, filepath.Base(reference[record.Command]))
		digest, size, err = candidateBinaryDigest(destination)
		after, statErr := os.Stat(destination)
		if err != nil || statErr != nil || digest != record.SHA256 || size != record.Bytes || !os.SameFile(exportInfo[record.Command], after) || !exportInfo[record.Command].ModTime().Equal(after.ModTime()) {
			t.Fatal("an existing candidate export was replaced or changed")
		}
		if record.Command == chosen {
			digest, size, err = candidateBinaryDigest(fresh)
			if err != nil || digest != record.SHA256 || size != record.Bytes {
				t.Fatal("fresh build reused changed bytes")
			}
		}
	}
	report := struct {
		SchemaVersion int                   `json:"schema_version"`
		Commands      int                   `json:"commands"`
		Individual    int                   `json:"individual_go_build_invocations"`
		Batch         int                   `json:"batch_go_build_invocations"`
		Rebuild       int                   `json:"rebuild_go_build_invocations"`
		Parallelism   int                   `json:"build_parallelism"`
		Equal         bool                  `json:"binary_bytes_equal"`
		Independent   bool                  `json:"independent_paths"`
		Mutation      bool                  `json:"private_mutation_isolated"`
		Fresh         bool                  `json:"fresh_rebuild"`
		Exports       bool                  `json:"existing_exports_unchanged"`
		ReferenceNS   int64                 `json:"reference_elapsed_ns"`
		BatchNS       int64                 `json:"batch_elapsed_ns"`
		Binaries      []queryCLIBatchBinary `json:"binaries"`
	}{1, len(queryCLIBatchNames), len(queryCLIBatchNames), 1, 1, 1, true, true, true, true, true, referenceElapsed, batchElapsed, records}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("query-cli-build-batch %s", raw)
	// These observed times include setup and filesystem work. The initial order
	// is not counterbalanced here; no timing threshold or speedup is qualified.
}

func TestQueryCLIBuildFailureHelper(t *testing.T) {
	if os.Getenv("SPV_QUERY_BUILD_FAILURE_HELPER") != "1" {
		return
	}
	buildQueryCLIs(t, "zenon-spv", "missing-query-cli-build-fixture")
	t.Fatal("failed build unexpectedly reached executable selection")
}

func TestQueryCLIBuildFailure(t *testing.T) {
	exports := t.TempDir()
	sentinel := filepath.Join(exports, "unrelated-evidence")
	if err := os.WriteFile(sentinel, []byte("retained control bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, "-test.run=^TestQueryCLIBuildFailureHelper$")
	cmd.Env = append(queryCLIEnvironment(), "SPV_QUERY_BUILD_FAILURE_HELPER=1", candidateExportEnvironment+"="+exports)
	cmd.WaitDelay = time.Second
	raw, runErr := cmd.CombinedOutput()
	if runErr == nil || ctx.Err() != nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 1 ||
		!bytes.Contains(raw, []byte("build selected CLIs:")) || bytes.Contains(raw, []byte("offline-pilot-binary ")) {
		t.Fatal("expected build failure did not stop before executable evidence")
	}
	entries, err := os.ReadDir(exports)
	if err != nil || len(entries) != 1 || entries[0].Name() != "unrelated-evidence" {
		t.Fatal("failed group exported a partial executable or changed unrelated evidence")
	}
	after, err := os.Stat(sentinel)
	content, readErr := os.ReadFile(sentinel)
	if err != nil || readErr != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || string(content) != "retained control bytes" {
		t.Fatal("expected build failure changed existing evidence")
	}
	t.Log(`query-cli-build-failure {"schema_version":1,"expected_child_exit":1,"deadline_exceeded":false,"binary_markers":0,"partial_exports":0,"existing_evidence_unchanged":true}`)
}
