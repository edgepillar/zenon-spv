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
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func sourceRootEvents(children int) []testEvent {
	return namedSourceRootEvents(sourceEnumerationPackage, sourceEnumerationTest, children)
}

func namedSourceRootEvents(pkg, root string, children int) []testEvent {
	events := []testEvent{{Action: "start", Package: pkg}, {Action: "run", Package: pkg, Test: root},
		{Action: "output", Package: pkg, Test: root, Output: "PRIVATE_OUTPUT /PRIVATE/PATH"}}
	for i := 0; i < children; i++ {
		name := fmt.Sprintf("%s/PRIVATE_DYNAMIC_%d", root, i)
		events = append(events, testEvent{Action: "run", Package: pkg, Test: name},
			testEvent{Action: "output", Package: pkg, Test: name, Output: "PRIVATE_CHILD_OUTPUT"},
			testEvent{Action: "pass", Package: pkg, Test: name})
	}
	return append(events, testEvent{Action: "pass", Package: pkg, Test: root}, testEvent{Action: "pass", Package: pkg})
}

func sourceRootCollect(t *testing.T, events []testEvent, group string, packages ...string) (*suiteCollector, []byte, error) {
	t.Helper()
	if len(packages) == 0 {
		packages = []string{sourceEnumerationPackage}
	}
	collector, err := newSuiteCollector(newCollector(nil), packages)
	if err != nil {
		t.Fatal(err)
	}
	collector.sourceRoots = newSourceRootCollector(group)
	var stream bytes.Buffer
	for _, event := range events {
		if err := json.NewEncoder(&stream).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	raw := slices.Clone(stream.Bytes())
	return collector, raw, collector.read(&stream)
}

func TestGroupedCLIBuildSourceRootReport(t *testing.T) {
	report := queryCLIBuildBatchReport{
		SchemaVersion: 1, Commands: 7, Individual: 7, Batch: 1, Rebuild: 1, Parallelism: 1,
		Equal: true, Independent: true, Mutation: true, Fresh: true, Exports: true,
		ReferenceNS: 40, BatchNS: 20,
	}
	for i, command := range queryCLIBuildReportCommands {
		report.Binaries = append(report.Binaries, queryCLIBuildOutput{command, fmt.Sprintf("%064x", i+1), 4096})
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	newRoot := func() sourceRootObservation {
		return sourceRootObservation{
			result:     sourceRootResult{Test: queryCLIBuildBatchTest, Status: "running"},
			reportSpec: sourceRootReportSpecs[queryCLIBuildBatchTest],
		}
	}
	root := newRoot()
	if err := root.observeReport(root.reportSpec.marker+string(raw[:128]), true); err != nil {
		t.Fatal(err)
	}
	if err := root.observeReport(string(raw[128:])+"\r\n", true); err != nil || !bytes.Equal(root.report, raw) {
		t.Fatal("complete grouped build evidence was lost", err)
	}
	if err := root.observeReport(root.reportSpec.marker+string(raw)+"\n", true); err == nil {
		t.Fatal("duplicate grouped build evidence was accepted")
	}
	for _, candidate := range [][]byte{
		bytes.Replace(raw, []byte(`"fresh_rebuild":true`), []byte(`"fresh_rebuild":false`), 1),
		bytes.Replace(raw, []byte(`"bytes":4096`), []byte(`"bytes":134217729`), 1),
		bytes.Replace(raw, []byte(`"command":"zenon-spv"`), []byte(`"command":"PRIVATE_PATH"`), 1),
		append([]byte(`{"private":"PRIVATE_PATH",`), raw[1:]...),
	} {
		bad := newRoot()
		if err := bad.observeReport(bad.reportSpec.marker+string(candidate)+"\n", true); err == nil || bad.report != nil {
			t.Fatal("invalid grouped build evidence entered the receipt")
		}
	}
}

func TestSourceRootEvidenceCompleteBoundAndPrivate(t *testing.T) {
	collector, raw, err := sourceRootCollect(t, sourceRootEvents(6), sourceEnumerationGroup)
	if err != nil || collector.finish(true) != "passed" {
		t.Fatal("complete source-root execution refused", err)
	}
	root := collector.sourceRoots.snapshot()
	want := &sourceRootEvidence{Format: "zenon-source-root-controls/v1", Group: "compiled-source-enumeration/v1", Status: "complete",
		Roots: []sourceRootResult{{Package: modulePath + "/tools/offline-pilot", Test: "TestCompiledPilotSourceEnumeration", Status: "pass", Passed: 6}}}
	if !reflect.DeepEqual(root, want) || collector.counts != (suiteCounts{RootTests: 1, Subtests: 6, Passed: 7}) {
		t.Fatal("specific-root evidence differs from the actual stream")
	}
	pkg, digest := collector.snapshot()
	sum := sha256.Sum256(raw)
	if digest != hex.EncodeToString(sum[:]) || collector.bytes != int64(len(raw)) || !collector.complete || len(pkg) != 1 {
		t.Fatal("complete stream binding was lost")
	}
	encoded, err := json.Marshal(root)
	if err != nil || bytes.Contains(encoded, []byte("PRIVATE")) || bytes.Contains(encoded, []byte("elapsed")) {
		t.Fatal("private labels, output or timing entered root evidence")
	}
	t.Logf("offline-pilot-source-root-contract %s", encoded)
	root.Roots[0].Passed = 100
	if collector.sourceRoots.snapshot().Roots[0].Passed != 6 {
		t.Fatal("receipt snapshot aliases mutable collector data")
	}
}

func TestSourceRootEvidenceCannotUseTotalsMissingRootsOrSkips(t *testing.T) {
	for _, count := range []int{0, 5, 7} {
		collector, _, err := sourceRootCollect(t, sourceRootEvents(count), sourceEnumerationGroup)
		if err != nil || collector.finish(true) != "incomplete" || collector.sourceRoots.snapshot().Status != "incomplete" {
			t.Fatal("wrong subtest count completed the required group", count, err)
		}
	}
	for _, action := range []string{"skip", "fail"} {
		events := sourceRootEvents(6)
		for i := range events {
			if strings.Contains(events[i].Test, "/") && events[i].Action == "pass" {
				events[i].Action = action
				break
			}
		}
		collector, _, err := sourceRootCollect(t, events, sourceEnumerationGroup)
		if err != nil || collector.finish(true) == "passed" || collector.sourceRoots.snapshot().Status != "incomplete" {
			t.Fatal("skipped or failed subtest became a required pass", action, err)
		}
	}
	events := sourceRootEvents(6)
	for i := range events {
		events[i].Test = strings.ReplaceAll(events[i].Test, sourceEnumerationTest, "TestOther")
	}
	collector, _, err := sourceRootCollect(t, events, sourceEnumerationGroup)
	if err != nil || collector.counts.Passed != 7 || collector.finish(true) != "incomplete" || collector.sourceRoots.snapshot().Roots[0].Status != "missing" {
		t.Fatal("aggregate passing totals supplied a missing required root", err)
	}
}

func TestSourceRootEvidenceLifecycleAndCompleteness(t *testing.T) {
	base := sourceRootEvents(6)
	cases := [][]testEvent{
		base[:len(base)-1], base[:len(base)-2],
		append(slices.Clone(base), base[len(base)-1]),
		append(slices.Clone(base[:3]), base[5:]...),
		append(slices.Clone(base[:3]), append([]testEvent{base[len(base)-2]}, base[3:]...)...),
	}
	for i, events := range cases {
		collector, _, err := sourceRootCollect(t, events, sourceEnumerationGroup)
		if err == nil && collector.finish(true) == "passed" {
			t.Fatal("invalid or incomplete lifecycle accepted", i)
		}
	}
	// A root cannot pass before an actually running child completes.
	events := slices.Clone(base)
	events[4], events[len(events)-2] = events[len(events)-2], events[4]
	if _, _, err := sourceRootCollect(t, events, sourceEnumerationGroup); err == nil {
		t.Fatal("premature required-root completion was accepted")
	}
	collector, _, err := sourceRootCollect(t, base, sourceEnumerationGroup)
	if err != nil || collector.finish(false) != "failed" {
		t.Fatal("successful counters replaced the actual failed process")
	}
	collector.complete = false
	if collector.finish(true) != "incomplete" {
		t.Fatal("unfinished input was treated as complete")
	}
}

func TestCompiledNativeObserverRootEvidence(t *testing.T) {
	const conformance = modulePath + "/internal/conformance"
	want := []sourceRootResult{
		{Package: conformance, Test: "TestCompiledAdvancingBlockObserver", Status: "pass", Passed: 9},
		{Package: conformance, Test: "TestCompiledNodeAccountBasicObserver", Status: "pass", Passed: 58},
		{Package: conformance, Test: "TestCompiledNodeAccountReceiveObserver", Status: "pass", Passed: 52},
		{Package: sourceEnumerationPackage, Test: sourceEnumerationTest, Status: "pass", Passed: 6},
	}
	for _, substitute := range []bool{false, true} {
		events := []testEvent{{Action: "start", Package: conformance}, {Action: "start", Package: sourceEnumerationPackage}}
		for i := len(want) - 1; i >= 0; i-- {
			row := want[i]
			if substitute && i == 1 {
				row.Test = "TestUnselectedObserver"
			}
			root := namedSourceRootEvents(row.Package, row.Test, row.Passed)
			events = append(events, root[1:len(root)-1]...)
		}
		events = append(events, testEvent{Action: "pass", Package: conformance},
			testEvent{Action: "pass", Package: sourceEnumerationPackage})
		collector, _, err := sourceRootCollect(t, events, compiledNativeObserverGroup, conformance, sourceEnumerationPackage)
		if err != nil || collector.counts != (suiteCounts{RootTests: 4, Subtests: 125, Passed: 129}) {
			t.Fatal("compiled native observer stream totals differ", err)
		}
		evidence := collector.sourceRoots.snapshot()
		if substitute {
			if collector.finish(true) != "incomplete" || evidence.Status != "incomplete" || evidence.Roots[1].Status != "missing" {
				t.Fatal("unselected observer satisfied the required root")
			}
		} else if collector.finish(true) != "passed" || evidence.Status != "complete" ||
			evidence.Group != compiledNativeObserverGroup || !reflect.DeepEqual(evidence.Roots, want) {
			t.Fatal("compiled native observer roots did not retain their own completions")
		}
	}
}

func TestCompiledNativePoWObserverRootEvidence(t *testing.T) {
	const conformance = modulePath + "/internal/conformance"
	const powTest = "TestCompiledNodeAccountPoWObserver"
	summary, err := json.Marshal(map[string]any{
		"schema_version": 1, "cases": 134, "observations": 64, "original_matched": 2,
		"collection_blocked": 62, "coherent_hash_signature_rejected": 62,
		"missing_commitment_refused": 4, "consumer_selection_mismatched": 4, "ordinary_commands": 4,
		"corpus_sha256":              "560ff77f5fe092e99222399309da164c0539dec749e95b0e1788cd52fe30716f",
		"node_revision":              "c64ed6279ff1d07335dab0ac36156dec8b5b71e9",
		"runtime_acceptance_changed": false, "account_pow_qualified": false,
		"new_signatures_generated": false, "network_pilot_qualified": false, "state_value_acceptance": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	log := testEvent{Action: "output", Package: conformance, Test: powTest,
		Output: "    PRIVATE_SOURCE_LOCATION: node-account-pow-observer " + string(summary) + "\n"}
	changed := log
	changed.Output = strings.Replace(log.Output, `"ordinary_commands":4`, `"ordinary_commands":5`, 1)
	truncated := log
	truncated.Output = strings.TrimSuffix(log.Output, "\n")
	other := log
	other.Test = "TestCompiledAdvancingBlockObserver"
	first, continuation := log, log
	first.Output, continuation.Output = log.Output[:len(log.Output)/2], log.Output[len(log.Output)/2:]
	oversized := first
	oversized.Output += strings.Repeat("a", len(log.Output))
	for _, tc := range []struct {
		name string
		logs []testEvent
	}{
		{"complete", []testEvent{log}}, {"split", []testEvent{first, continuation}},
		{"oversized", []testEvent{oversized}}, {"missing", nil}, {"other_root", []testEvent{other}},
		{"changed", []testEvent{changed}}, {"partial", []testEvent{truncated}}, {"duplicate", []testEvent{log, log}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := []testEvent{{Action: "start", Package: conformance}, {Action: "start", Package: sourceEnumerationPackage}}
			for _, row := range compiledNativeObserverRoots {
				sequence := namedSourceRootEvents(row.packageName, row.test, row.subtests)
				if row.test == other.Test && tc.name == "other_root" {
					sequence = slices.Insert(sequence, len(sequence)-2, tc.logs...)
				}
				events = append(events, sequence[1:len(sequence)-1]...)
			}
			pow := namedSourceRootEvents(conformance, powTest, 134)
			events = append(events, pow[1:len(pow)-2]...)
			if tc.name != "other_root" {
				events = append(events, tc.logs...)
			}
			events = append(events, pow[len(pow)-2:]...)
			events = append(events, testEvent{Action: "pass", Package: sourceEnumerationPackage})
			collector, _, err := sourceRootCollect(t, events, compiledNativeObserverGroupV2, conformance, sourceEnumerationPackage)
			if tc.name != "complete" && tc.name != "split" {
				if err == nil && collector.finish(true) == "passed" {
					t.Fatal("invalid or missing PoW report qualified")
				}
				return
			}
			if err != nil || collector.finish(true) != "passed" ||
				collector.counts != (suiteCounts{RootTests: 5, Subtests: 259, Passed: 264}) {
				t.Fatal("complete ordinary-parent observer group refused", err)
			}
			evidence := collector.sourceRoots.snapshot()
			if evidence.Format != "zenon-source-root-controls/v2" || evidence.Status != "complete" ||
				!bytes.Equal(evidence.NodeAccountPoWObserver, summary) ||
				evidence.Roots[4] != (sourceRootResult{Package: conformance, Test: powTest, Status: "pass", Passed: 134}) {
				t.Fatal("PoW report or its exact root was lost")
			}
			encoded, err := json.Marshal(evidence)
			if err != nil || bytes.Contains(encoded, []byte("PRIVATE")) {
				t.Fatal("private output entered the fixed PoW report", err)
			}
			evidence.NodeAccountPoWObserver[0] = 0
			if !bytes.Equal(collector.sourceRoots.snapshot().NodeAccountPoWObserver, summary) {
				t.Fatal("receipt snapshot aliases the original report")
			}
		})
	}
}

func TestSourceRootEvidenceOptInAndLegacyShape(t *testing.T) {
	collector, _, err := sourceRootCollect(t, sourceRootEvents(6), "")
	if err != nil || collector.finish(true) != "passed" || collector.sourceRoots.snapshot() != nil {
		t.Fatal("default whole-suite behavior changed", err)
	}
	raw, err := json.Marshal(suiteReceipt{Format: "zenon-root-suite/v3"})
	if err != nil || bytes.Contains(raw, []byte("source_root_controls")) {
		t.Fatal("opt-in evidence changed the default receipt shape", err)
	}
	for _, args := range [][]string{
		{"--suite-root-group", "PRIVATE"}, {"--suite-root-group", ""},
		{"--suite-root-group", sourceEnumerationGroup},
		{"--suite-root-group", compiledNativeObserverGroup},
		{"--suite-root-group", compiledNativeObserverGroupV2},
		{"--suite-root-group", compiledNativeObserverGroupV3},
		{"--suite-root-group", sourceEnumerationGroup, "--suite-root-group", compiledNativeObserverGroup},
		{"--suite-root-group", sourceEnumerationGroup, "--suite-root-group", sourceEnumerationGroup},
	} {
		var out, diagnostic bytes.Buffer
		if run(args, &out, &diagnostic) != 64 || out.Len() != 0 || bytes.Contains(diagnostic.Bytes(), []byte("PRIVATE")) {
			t.Fatal("invalid or non-full-suite selector reached setup or disclosed input")
		}
	}
}

// This small ordinary Go package checks real test2json lifecycle/EOF behavior.
// It models the fixed root and six subtests, not the actual enumeration code.
// The unchanged real enumeration test remains required in hosted full suites.
func TestSourceRootEvidenceActualGoStream(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("native Go tool is required")
	}
	root := t.TempDir()
	files := map[string]string{
		"go.mod": "module " + sourceEnumerationPackage + "\n\ngo 1.25.0\n",
		"fixture_test.go": `package main
import "testing"
func TestCompiledPilotSourceEnumeration(t *testing.T) {
 for _, name := range []string{"a", "b", "c", "d", "e", "f"} {
  t.Run(name, func(t *testing.T) { t.Log("PRIVATE_NATIVE_LABEL") })
 }
}
`,
	}
	for name, raw := range files {
		if os.WriteFile(filepath.Join(root, name), []byte(raw), 0o600) != nil {
			t.Fatal("cannot prepare native event fixture")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goTool, "test", "-json", "-count=1", "-timeout=30s", ".")
	cmd.Dir, cmd.Env, cmd.WaitDelay = root, pilotEnvironment(goTool), time.Second
	stream, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal("cannot capture native event stream")
	}
	collector, err := newSuiteCollector(newCollector(nil), []string{sourceEnumerationPackage})
	if err != nil {
		t.Fatal("cannot initialize fixture collector")
	}
	collector.sourceRoots = newSourceRootCollector(sourceEnumerationGroup)
	if cmd.Start() != nil {
		t.Fatal("cannot start native event fixture")
	}
	readErr := collector.read(stream)
	waitErr := cmd.Wait()
	if readErr != nil || waitErr != nil || ctx.Err() != nil || collector.finish(true) != "passed" || !collector.sourceRoots.complete() {
		t.Fatal("actual native event stream did not complete its bounded group")
	}
	raw, err := json.Marshal(collector.sourceRoots.snapshot())
	if err != nil || bytes.Contains(raw, []byte("PRIVATE")) || collector.sourceRoots.snapshot().Roots[0].Passed != 6 {
		t.Fatal("native event fixture leaked labels or lost subtest completions")
	}
}
