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
	pkg, root := sourceEnumerationPackage, sourceEnumerationTest
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

func sourceRootCollect(t *testing.T, events []testEvent, enabled bool) (*suiteCollector, []byte, error) {
	t.Helper()
	collector, err := newSuiteCollector(newCollector(nil), []string{sourceEnumerationPackage})
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		collector.sourceRoots = newSourceRootCollector()
	}
	var stream bytes.Buffer
	for _, event := range events {
		if err := json.NewEncoder(&stream).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	raw := slices.Clone(stream.Bytes())
	return collector, raw, collector.read(&stream)
}

func TestSourceRootEvidenceCompleteBoundAndPrivate(t *testing.T) {
	collector, raw, err := sourceRootCollect(t, sourceRootEvents(6), true)
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
		collector, _, err := sourceRootCollect(t, sourceRootEvents(count), true)
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
		collector, _, err := sourceRootCollect(t, events, true)
		if err != nil || collector.finish(true) == "passed" || collector.sourceRoots.snapshot().Status != "incomplete" {
			t.Fatal("skipped or failed subtest became a required pass", action, err)
		}
	}
	events := sourceRootEvents(6)
	for i := range events {
		events[i].Test = strings.ReplaceAll(events[i].Test, sourceEnumerationTest, "TestOther")
	}
	collector, _, err := sourceRootCollect(t, events, true)
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
		collector, _, err := sourceRootCollect(t, events, true)
		if err == nil && collector.finish(true) == "passed" {
			t.Fatal("invalid or incomplete lifecycle accepted", i)
		}
	}
	// A root cannot pass before an actually running child completes.
	events := slices.Clone(base)
	events[4], events[len(events)-2] = events[len(events)-2], events[4]
	if _, _, err := sourceRootCollect(t, events, true); err == nil {
		t.Fatal("premature required-root completion was accepted")
	}
	collector, _, err := sourceRootCollect(t, base, true)
	if err != nil || collector.finish(false) != "failed" {
		t.Fatal("successful counters replaced the actual failed process")
	}
	collector.complete = false
	if collector.finish(true) != "incomplete" {
		t.Fatal("unfinished input was treated as complete")
	}
}

func TestSourceRootEvidenceOptInAndLegacyShape(t *testing.T) {
	collector, _, err := sourceRootCollect(t, sourceRootEvents(6), false)
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
	collector.sourceRoots = newSourceRootCollector()
	if cmd.Start() != nil {
		t.Fatal("cannot start native event fixture")
	}
	readErr := collector.read(stream)
	waitErr := cmd.Wait()
	if readErr != nil || waitErr != nil || ctx.Err() != nil || collector.finish(true) != "passed" || !collector.sourceRoots.complete() {
		t.Fatal("actual native event stream did not complete its bounded group")
	}
	raw, err := json.Marshal(collector.sourceRoots.snapshot())
	if err != nil || bytes.Contains(raw, []byte("PRIVATE")) || collector.sourceRoots.result.Passed != 6 {
		t.Fatal("native event fixture leaked labels or lost subtest completions")
	}
}
