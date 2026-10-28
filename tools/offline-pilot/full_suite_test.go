package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func suiteFixture() []testEvent {
	events := sampleEvents()
	pkg := events[0].Package
	// An unselected test in a selected package must neither disappear from the
	// whole-suite accounting nor inject markers into the selected report.
	extra := []testEvent{
		{Action: "run", Package: pkg, Test: "TestOther"},
		{Action: "output", Package: pkg, Test: "TestOther", Output: binaryMarker + "PRIVATE_INVALID_RECORD"},
		{Action: "run", Package: pkg, Test: "TestOther/PRIVATE_CASE"},
		{Action: "skip", Package: pkg, Test: "TestOther/PRIVATE_CASE"},
		{Action: "pass", Package: pkg, Test: "TestOther"},
	}
	events = append(events[:6], append(extra, events[6:]...)...)
	other := modulePath + "/internal/other"
	return append(events,
		testEvent{Action: "start", Package: other},
		testEvent{Action: "run", Package: other, Test: "TestIndependent"},
		testEvent{Action: "pass", Package: other, Test: "TestIndependent"},
		testEvent{Action: "pass", Package: other},
		testEvent{Action: "start", Package: modulePath + "/cmd/no-tests"},
		testEvent{Action: "skip", Package: modulePath + "/cmd/no-tests"})
}

func collectSuite(t *testing.T, events []testEvent) (*suiteCollector, []byte, error) {
	t.Helper()
	var stream bytes.Buffer
	for _, event := range events {
		if err := json.NewEncoder(&stream).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	raw := slices.Clone(stream.Bytes())
	c, err := newSuiteCollector(newCollector(sampleManifest()), []string{
		modulePath + "/internal/conformance", modulePath + "/internal/other", modulePath + "/cmd/no-tests",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, raw, c.read(&stream)
}

func TestFullSuiteProjectionMatchesSelectedReport(t *testing.T) {
	selected, err := collectEvents(t, sampleEvents())
	if err != nil || selected.finish(true) != "passed" {
		t.Fatal("selected reference failed")
	}
	full, raw, err := collectSuite(t, suiteFixture())
	if err != nil || full.finish(true) != "passed" || full.selected.finish(true) != "passed" {
		t.Fatal("complete full-suite execution was refused")
	}
	if !reflect.DeepEqual(selected.cases, full.selected.cases) || !reflect.DeepEqual(selected.skips.snapshot(), full.selected.skips.snapshot()) {
		t.Fatal("whole-suite projection changed the selected cases or skip ledger")
	}
	if full.counts != (suiteCounts{RootTests: 3, Subtests: 2, Passed: 4, Skipped: 1}) {
		t.Fatal("unselected test or skip disappeared from whole-suite accounting")
	}
	packages, digest := full.snapshot()
	expected := sha256.Sum256(raw)
	if full.bytes != int64(len(raw)) || digest != hex.EncodeToString(expected[:]) || len(packages) != 3 || !full.complete {
		t.Fatal("event stream digest, byte count or package inventory was lost")
	}
	report, err := json.Marshal(struct {
		Packages []suitePackage
		Tests    suiteCounts
		Cases    []caseResult
	}{packages, full.counts, full.selected.cases})
	if err != nil || bytes.Contains(report, []byte("PRIVATE")) {
		t.Fatal("unselected diagnostics or dynamic test names reached the report")
	}
}

func TestFullSuiteRefusesUnselectedFailuresAndIncompleteExecution(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]testEvent) []testEvent
	}{
		{"unselected test failure", func(e []testEvent) []testEvent { e[10].Action = "fail"; return e }},
		{"unselected package failure", func(e []testEvent) []testEvent { e[15].Action = "fail"; return e }},
		{"missing expected package", func(e []testEvent) []testEvent { return e[:16] }},
		{"missing package completion", func(e []testEvent) []testEvent { return e[:len(e)-1] }},
		{"unfinished unselected test", func(e []testEvent) []testEvent { return append(e[:14], e[15:]...) }},
		{"duplicate test", func(e []testEvent) []testEvent { return append(e[:11], append([]testEvent{e[6]}, e[11:]...)...) }},
		{"duplicate package", func(e []testEvent) []testEvent { return append(e, e[12]) }},
		{"completion without start", func(e []testEvent) []testEvent { return e[1:] }},
		{"unexpected package", func(e []testEvent) []testEvent { e[12].Package = "PRIVATE_PACKAGE"; return e }},
		{"unexpected selected test marker", func(e []testEvent) []testEvent { e[2].Output = binaryMarker + "PRIVATE_INVALID_RECORD"; return e }},
		{"orphan subtest", func(e []testEvent) []testEvent { e[8].Test = "Absent/PRIVATE_CASE"; return e }},
		{"unknown action", func(e []testEvent) []testEvent { e[7].Action = "PRIVATE_ACTION"; return e }},
		{"test after package completion", func(e []testEvent) []testEvent { return append(e, e[6]) }},
		{"output after completion", func(e []testEvent) []testEvent { return append(e[:11], append([]testEvent{e[7]}, e[11:]...)...) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, err := collectSuite(t, tc.mutate(suiteFixture()))
			if err == nil && c.finish(true) == "passed" {
				t.Fatal("failed or incomplete execution accepted after selected scenarios passed")
			}
			if err != nil && strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("rejection disclosed input")
			}
		})
	}
	c, _, err := collectSuite(t, suiteFixture())
	if err != nil || c.finish(false) != "failed" {
		t.Fatal("actual process failure was overridden by passing events")
	}
}

func TestFullSuitePackageInventoryBounds(t *testing.T) {
	valid := modulePath + "/internal/conformance\n" + modulePath + "/cmd/no-tests\n"
	got, err := readSuitePackages(strings.NewReader(valid))
	if err != nil || len(got) != 2 || !slices.IsSorted(got) {
		t.Fatal("valid root module inventory refused")
	}
	for _, input := range []string{"", "PRIVATE_PACKAGE\n", modulePath + "/../private\n", valid + valid, strings.Repeat("x", 4096)} {
		if _, err := readSuitePackages(strings.NewReader(input)); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid package inventory accepted or disclosed")
		}
	}
	if _, err := newSuiteCollector(newCollector(sampleManifest()), []string{modulePath}); err == nil {
		t.Fatal("selected package absent from inventory was accepted")
	}
}

type suiteReadFailure struct{}

func (suiteReadFailure) Read([]byte) (int, error) { return 0, errors.New("PRIVATE_STREAM") }

func TestFullSuiteStreamBoundsAndReadFailure(t *testing.T) {
	for _, input := range []io.Reader{strings.NewReader("PRIVATE_NOT_JSON\n"), strings.NewReader(strings.Repeat(" ", 1<<20)), suiteReadFailure{}} {
		c, err := newSuiteCollector(newCollector(sampleManifest()), []string{modulePath + "/internal/conformance"})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.read(input); err == nil || strings.Contains(err.Error(), "PRIVATE") || c.complete {
			t.Fatal("invalid stream claimed complete or disclosed input")
		}
	}
	// Valid bounded lines exceed the aggregate cap without a giant allocation.
	line, _ := json.Marshal(testEvent{Action: "output", Package: "build-dependency", Output: strings.Repeat("x", 65536)})
	text := string(append(line, '\n'))
	readers := make([]io.Reader, 513)
	for i := range readers {
		readers[i] = strings.NewReader(text)
	}
	input := io.MultiReader(readers...)
	c, _ := newSuiteCollector(newCollector(sampleManifest()), []string{modulePath + "/internal/conformance"})
	if c.read(input) == nil || c.complete || c.bytes > suiteStreamLimit+1 {
		t.Fatal("aggregate stream cap was not enforced")
	}
}

func TestFullSuiteArgumentsPreserveCompleteUncachedExecution(t *testing.T) {
	for _, race := range []bool{true, false} {
		args := fullSuiteArguments(race, 10*time.Minute, "coverage.out")
		if !reflect.DeepEqual(args[:2], []string{"test", "-p"}) || args[2] != "1" || args[len(args)-1] != "./..." || slices.Contains(args, "-run") {
			t.Fatal("whole root module was filtered or package orchestration changed")
		}
		for _, option := range []string{"-json", "-count=1", "-timeout=10m0s", "-coverprofile=coverage.out"} {
			if !slices.Contains(args, option) {
				t.Fatal("full-suite execution policy missing")
			}
		}
		if slices.Contains(args, "-race") != race {
			t.Fatal("parent race setting changed")
		}
	}
	for _, args := range [][]string{
		{"--full-suite"}, {"--package-timeout", "10m"}, {"--coverage"}, {"--suite-receipt", "PRIVATE_PATH"},
		{"--full-suite", "--package-timeout", "20m", "--suite-receipt", filepath.Join(t.TempDir(), "receipt.json")},
		{"--full-suite", "--package-timeout", "10m", "--suite-receipt", "PRIVATE_RELATIVE"},
	} {
		var stdout, stderr bytes.Buffer
		if run(args, &stdout, &stderr) != 64 || stdout.Len() != 0 || strings.Contains(stderr.String(), "PRIVATE") {
			t.Fatal("invalid mode combination reached setup or disclosed arguments")
		}
	}
}

func TestFullSuiteReceiptIsIndependentAndExclusive(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	export := filepath.Join(root, "candidate")
	if err := os.Mkdir(export, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "receipt.json")
	for _, path := range []string{filepath.Join(root, "receipt.json"), filepath.Join(export, "receipt.json"), "relative"} {
		if file, err := openSuiteReceipt(path, export); err == nil {
			file.Close()
			t.Fatal("receipt destination inside source/candidate or relative path accepted")
		}
	}
	file, err := openSuiteReceipt(outside, export)
	if err != nil {
		t.Fatal("independent receipt refused")
	}
	value := suiteReceipt{Format: "zenon-root-suite/v1", Status: "failed", ProcessOK: false, StreamComplete: false}
	if writeSuiteReceipt(file, value) != nil {
		t.Fatal("failure receipt was not preserved")
	}
	before, err := os.ReadFile(outside)
	if err != nil || !bytes.Contains(before, []byte(`"status": "failed"`)) {
		t.Fatal("failure receipt lost")
	}
	if file, err := openSuiteReceipt(outside, export); err == nil {
		file.Close()
		t.Fatal("existing receipt overwritten")
	}
	after, _ := os.ReadFile(outside)
	if !bytes.Equal(before, after) {
		t.Fatal("existing evidence changed")
	}
	closed, err := os.Create(filepath.Join(t.TempDir(), "closed.json"))
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	if writeSuiteReceipt(closed, value) == nil {
		t.Fatal("closed output reported success")
	}
}

func TestFullSuiteActualProcessCompletion(t *testing.T) {
	t.Setenv(pilotHelperEnvironment, "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	self, err := os.Executable()
	if err != nil {
		t.Fatal("cannot identify native helper")
	}
	for _, mode := range []string{"complete", "failed after complete events", "deadline after complete events", "malformed stream"} {
		t.Run(mode, func(t *testing.T) {
			c, err := newSuiteCollector(newCollector(sampleManifest()), []string{modulePath + "/internal/conformance"})
			if err != nil {
				t.Fatal(err)
			}
			deadline := 5 * time.Second
			if mode == "deadline after complete events" {
				deadline = 500 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()
			ok, category := runTestProcess(ctx, self, []string{"-test.run=^TestPilotProcessHelper$", "--", mode, "unused"}, os.Environ(), c.read)
			if mode == "complete" {
				if !ok || category != nil || c.finish(ok) != "passed" || c.selected.finish(ok) != "passed" {
					t.Fatal("complete actual execution lost its trailing events")
				}
			} else if ok || category == nil || c.finish(ok) == "passed" {
				t.Fatal("passing observed events overrode a failed, timed out or malformed actual execution")
			}
		})
	}
}
