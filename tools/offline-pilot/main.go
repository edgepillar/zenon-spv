// offline-pilot runs a fixed local conformance selection and emits a compact,
// privacy-filtered execution report. It does not contact public RPC services.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/0x3639/zenon-spv/internal/buildinfo"
)

type pilotReport struct {
	SchemaVersion   int              `json:"schema_version"`
	Mode            string           `json:"mode"`
	Status          string           `json:"status"`
	Error           *string          `json:"error"`
	Runner          buildinfo.Report `json:"runner"`
	Race            bool             `json:"test_parent_race_enabled"`
	Source          sourceRecord     `json:"source"`
	InputsUnchanged bool             `json:"source_matches_after_run"`
	Corpus          []corpusRecord   `json:"corpus"`
	Cases           []caseResult     `json:"cases"`
	Caveats         []string         `json:"caveats"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("offline-pilot", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	timeout := fs.Duration("timeout", 10*time.Minute, "overall test timeout")
	race := fs.Bool("race", false, "instrument test parents with the race detector")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return writeReport(stdout, stderr, []byte("Usage: offline-pilot [--race] [--timeout 10m]\nRun from the repository root with dependencies already cached.\n"), 0)
		}
		_, _ = fmt.Fprintln(stderr, "offline-pilot: invalid arguments; use --help")
		return 64
	}
	if fs.NArg() != 0 || *timeout <= 0 || *timeout > time.Hour {
		_, _ = fmt.Fprintln(stderr, "offline-pilot: invalid arguments; use --help")
		return 64
	}
	before, err := captureSource()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "offline-pilot: source setup failed; run from the repository root")
		return 70
	}
	corpus, err := captureCorpus()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "offline-pilot: corpus setup failed")
		return 70
	}
	collector := newCollector(scenarios)
	report := pilotReport{
		SchemaVersion: 1, Mode: "offline_synthetic", Status: "incomplete", Race: *race,
		Runner: buildinfo.Capture("offline-pilot"), Source: before, Corpus: corpus,
		Caveats: []string{
			"Selected tests use synthetic fixtures and loopback RPC; this is not a live-network pilot.",
			"Anchors, activation profiles, producer schedules, and retained-state provenance are external trust inputs.",
			"No canonicality, consensus finality, state-transition execution, or state-value proof is established.",
			"Input and executable hashes describe this local run; they are not signed attestations or proof of a reproducible build.",
			"Go module cache, toolchain, build environment, and local test execution remain trusted.",
			"Compiled child CLIs use ordinary builds even when test parents enable the race detector.",
			"A passed scenario can contain skipped subtests; inspect each scenario's status and skip count.",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	goTool, err := exec.LookPath("go")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "offline-pilot: Go toolchain is unavailable on PATH")
		return 70
	}
	cmd := exec.CommandContext(ctx, goTool, testArguments(scenarios, *race)...)
	cmd.Env, cmd.Stderr = pilotEnvironment(goTool), io.Discard
	cmd.WaitDelay = 2 * time.Second
	stream, err := cmd.StdoutPipe()
	processOK := false
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		report.Error = errorCategory("test_start")
	} else {
		readErr := collector.read(stream)
		if readErr != nil {
			cancel() // Stop producing data before waiting on a rejected stream.
		}
		waitErr := cmd.Wait()
		processOK = waitErr == nil
		switch {
		case readErr != nil:
			report.Error = errorCategory("test_stream")
		case ctx.Err() != nil:
			report.Error = errorCategory("test_timeout")
		case waitErr != nil:
			report.Error = errorCategory("test_process")
		}
	}
	report.Status = collector.finish(processOK)
	report.Cases = collector.cases
	after, err := captureSource()
	report.InputsUnchanged = err == nil && reflect.DeepEqual(before, after)
	if !report.InputsUnchanged {
		report.Status, report.Error = "incomplete", errorCategory("source_changed")
	} else if report.Error != nil {
		report.Status = "failed"
	}
	code := 0
	if report.Status != "passed" && report.Status != "passed_with_skips" {
		code = 1
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "offline-pilot: report encoding failed")
		return 70
	}
	return writeReport(stdout, stderr, append(raw, '\n'), code)
}

func testArguments(manifest []scenario, race bool) []string {
	names, packages := make([]string, 0, len(manifest)), make([]string, 0)
	for _, s := range manifest {
		names = append(names, s.Test)
		if !slices.Contains(packages, "./"+s.Package) {
			packages = append(packages, "./"+s.Package)
		}
	}
	args := []string{"test", "-json", "-count=1", "-timeout=5m"}
	if race {
		args = append(args, "-race")
	}
	args = append(args, "-run", "^("+strings.Join(names, "|")+")$")
	return append(args, packages...)
}

func pilotEnvironment(goTool string) []string {
	overrides := []string{"GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=", "GOENV=off",
		"GOPRIVATE=", "GONOPROXY=none", "GOVCS=*:off",
		"GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH,
		"PATH=" + filepath.Dir(goTool) + string(os.PathListSeparator) + os.Getenv("PATH")}
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		key = strings.ToUpper(key)
		if strings.HasPrefix(key, "ZENON_SPV_") || slices.ContainsFunc(overrides, func(v string) bool { return strings.HasPrefix(v, key+"=") }) {
			continue
		}
		env = append(env, value)
	}
	return append(env, overrides...)
}

func errorCategory(value string) *string { return &value }

func writeReport(stdout, stderr io.Writer, raw []byte, code int) int {
	n, err := stdout.Write(raw)
	if err != nil || n != len(raw) {
		_, _ = fmt.Fprintln(stderr, "offline-pilot: report output failed")
		return 70
	}
	return code
}
