// offline-pilot runs a fixed local conformance selection and emits a compact,
// privacy-filtered execution report. It does not contact public RPC services.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	SkipLedger      *skipLedger      `json:"skip_ledger,omitempty"`
	Caveats         []string         `json:"caveats"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("offline-pilot", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	timeout := fs.Duration("timeout", 10*time.Minute, "overall test timeout")
	race := fs.Bool("race", false, "instrument test parents with the race detector")
	fullSuite := fs.Bool("full-suite", false, "derive the selected report from one complete root-module test run")
	packageTimeout := fs.Duration("package-timeout", 0, "explicit per-package deadline for full-suite mode")
	suiteReceiptPath := fs.String("suite-receipt", "", "new absolute receipt outside the checkout and candidate directory")
	coverage := fs.Bool("coverage", false, "write coverage.out in full-suite mode")
	var exportDir string
	fs.Func("export-binaries", "new absolute directory outside the checkout", func(value string) error {
		if exportDir != "" || value == "" || len(value) > 4096 || !filepath.IsAbs(value) {
			return errors.New("invalid candidate directory")
		}
		exportDir = filepath.Clean(value)
		return nil
	})
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return writeReport(stdout, stderr, []byte("Usage: offline-pilot [--race] [--timeout 10m] [--export-binaries ABSOLUTE_NEW_DIRECTORY]\nFull root module: add --full-suite --package-timeout 10m --suite-receipt ABSOLUTE_NEW_FILE [--coverage].\nRun from the repository root with dependencies already cached.\n"), 0)
		}
		_, _ = fmt.Fprintln(stderr, "offline-pilot: invalid arguments; use --help")
		return 64
	}
	if fs.NArg() != 0 || *timeout <= 0 || *timeout > time.Hour ||
		(*fullSuite && (*packageTimeout <= 0 || *packageTimeout > *timeout || *suiteReceiptPath == "" || len(*suiteReceiptPath) > 4096 || !filepath.IsAbs(*suiteReceiptPath))) ||
		(!*fullSuite && (*packageTimeout != 0 || *suiteReceiptPath != "" || *coverage)) {
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
		SchemaVersion: 2, Mode: "offline_synthetic", Status: "incomplete", Race: *race,
		Runner: buildinfo.Capture("offline-pilot"), Source: before, Corpus: corpus,
		Caveats: []string{
			"Selected tests use synthetic fixtures and loopback RPC; this is not a live-network pilot.",
			"Anchors, activation profiles, producer schedules, and retained-state provenance are external trust inputs.",
			"No canonicality, consensus finality, state-transition execution, or state-value proof is established.",
			"Input and executable hashes describe this local run; they are not signed attestations or proof of a reproducible build.",
			"Go module cache, toolchain, build environment, and local test execution remain trusted.",
			"Compiled child CLIs use ordinary builds even when test parents enable the race detector.",
			"A passed scenario can contain skipped subtests; inspect the source-owned skip ledger and its diagnostic coverage.",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	goTool, err := exec.LookPath("go")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "offline-pilot: Go toolchain is unavailable on PATH")
		return 70
	}
	if exportDir != "" {
		exportDir, err = prepareCandidateDirectory(exportDir)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "offline-pilot: candidate directory setup failed")
			return 70
		}
	}
	var receiptFile *os.File
	if *fullSuite {
		receiptFile, err = openSuiteReceipt(*suiteReceiptPath, exportDir)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "offline-pilot: suite receipt setup failed")
			return 70
		}
		defer func() { _ = receiptFile.Close() }() // Fallback for early return; the receipt writer checks its close.
	}
	env := pilotEnvironment(goTool)
	if exportDir != "" {
		env = append(env, candidateExportEnvironment+"="+exportDir)
	}
	var suite *suiteCollector
	var processOK, inventoryOK bool
	var processError *string
	if *fullSuite {
		var packages []string
		inventoryOK, _ = runTestProcess(ctx, goTool, []string{"list", "./..."}, env, func(r io.Reader) error {
			var listErr error
			packages, listErr = readSuitePackages(r)
			return listErr
		})
		if !inventoryOK {
			processError = errorCategory("suite_inventory")
		} else {
			suite, err = newSuiteCollector(collector, packages)
			if err != nil {
				processError = errorCategory("suite_inventory")
			} else {
				profile := ""
				if *coverage {
					profile = "coverage.out"
				}
				processOK, processError = runTestProcess(ctx, goTool, fullSuiteArguments(*race, *packageTimeout, profile), env, suite.read)
			}
		}
	} else {
		processOK, processError = runTestProcess(ctx, goTool, testArguments(scenarios, *race, *timeout), env, collector.read)
	}
	report.Error = processError
	report.Status = collector.finish(processOK)
	if suite != nil && suite.finish(processOK) != "passed" {
		report.Status = suite.finish(processOK)
		if processError == nil {
			report.Error = errorCategory("suite_incomplete")
		}
	}
	report.Cases = collector.cases
	report.SkipLedger = collector.skips.snapshot()
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
	raw = append(raw, '\n')
	if exportDir != "" && code == 0 {
		if err := finalizeCandidate(exportDir, report, raw); err != nil {
			report.Status, report.Error = "failed", errorCategory("candidate_export")
			raw, err = json.MarshalIndent(report, "", "  ")
			if err != nil {
				_, _ = fmt.Fprintln(stderr, "offline-pilot: report encoding failed")
				return 70
			}
			raw, code = append(raw, '\n'), 70
		}
	}
	if receiptFile != nil {
		digest := sha256.Sum256(raw)
		receipt := suiteReceipt{
			Format: "zenon-root-suite/v1", Status: report.Status, Error: report.Error, Source: before,
			InputsUnchanged: report.InputsUnchanged, Race: *race, Coverage: *coverage,
			PackageTimeout: packageTimeout.String(), OverallTimeout: timeout.String(),
			InventoryOK: inventoryOK, ProcessOK: processOK, SelectedScenarios: len(scenarios),
			SelectedReportSHA: hex.EncodeToString(digest[:]), Packages: []suitePackage{},
		}
		if suite != nil {
			receipt.Packages, receipt.StreamSHA256 = suite.snapshot()
			receipt.Tests, receipt.StreamBytes, receipt.StreamComplete = suite.counts, suite.bytes, suite.complete
		}
		if err := writeSuiteReceipt(receiptFile, receipt); err != nil {
			_, _ = fmt.Fprintln(stderr, "offline-pilot: suite receipt output failed")
			return 70
		}
	}
	return writeReport(stdout, stderr, raw, code)
}

func testArguments(manifest []scenario, race bool, timeout time.Duration) []string {
	names, packages := make([]string, 0, len(manifest)), make([]string, 0)
	for _, s := range manifest {
		names = append(names, s.Test)
		if !slices.Contains(packages, "./"+s.Package) {
			packages = append(packages, "./"+s.Package)
		}
	}
	// The caller-selected overall context still bounds the complete process.
	// Do not impose a shorter hidden package deadline on a larger selection.
	args := []string{"test", "-json", "-count=1", "-timeout=" + timeout.String()}
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
