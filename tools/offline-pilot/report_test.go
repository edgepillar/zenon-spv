package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func sampleManifest() []scenario {
	return []scenario{{"sample", "internal/conformance", "TestExample", []string{"zenon-spv"}}}
}

func sampleEvents() []testEvent {
	pkg := modulePath + "/internal/conformance"
	return []testEvent{
		{Action: "start", Package: pkg},
		{Action: "run", Package: pkg, Test: "TestExample"},
		{Action: "output", Package: pkg, Test: "TestExample", Output: "    helper.go:1: " + binaryMarker + `{"command":"zenon-spv","sha256":"` + strings.Repeat("a", 64) + `"}` + "\n"},
		{Action: "run", Package: pkg, Test: "TestExample/child"},
		{Action: "pass", Package: pkg, Test: "TestExample/child"},
		{Action: "pass", Package: pkg, Test: "TestExample"},
		{Action: "pass", Package: pkg},
	}
}

func collectEvents(t *testing.T, events []testEvent) (*eventCollector, error) {
	t.Helper()
	var stream bytes.Buffer
	for _, event := range events {
		if err := json.NewEncoder(&stream).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	c := newCollector(sampleManifest())
	return c, c.read(&stream)
}

func TestReportRequiresCompleteUncachedExecution(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		mutate       func([]testEvent) []testEvent
		processOK    bool
	}{
		{"pass", "passed", func(e []testEvent) []testEvent { return e }, true},
		{"skipped child", "passed_with_skips", func(e []testEvent) []testEvent { e[4].Action = "skip"; return e }, true},
		{"skipped root", "incomplete", func(e []testEvent) []testEvent { e[5].Action = "skip"; return e }, true},
		{"failed child", "failed", func(e []testEvent) []testEvent { e[4].Action = "fail"; return e }, true},
		{"failed root", "failed", func(e []testEvent) []testEvent { e[5].Action = "fail"; return e }, true},
		{"no tests", "incomplete", func(e []testEvent) []testEvent { return []testEvent{e[0], e[6]} }, true},
		{"missing package completion", "incomplete", func(e []testEvent) []testEvent { return e[:6] }, true},
		{"unfinished child", "incomplete", func(e []testEvent) []testEvent { return append(e[:4], e[5:]...) }, true},
		{"missing executable", "incomplete", func(e []testEvent) []testEvent { e[2].Output = "regular output"; return e }, true},
		{"failed process after passing tests", "failed", func(e []testEvent) []testEvent { return e }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := collectEvents(t, tc.mutate(sampleEvents()))
			if err != nil {
				t.Fatal(err)
			}
			if got := c.finish(tc.processOK); got != tc.status {
				t.Fatalf("status=%s, want %s", got, tc.status)
			}
		})
	}
}

func TestReportRejectsAmbiguousOrUnexpectedExecution(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]testEvent) []testEvent
	}{
		{"duplicate test", func(e []testEvent) []testEvent { return append(e, e[1]) }},
		{"duplicate completion", func(e []testEvent) []testEvent { return append(e, e[5]) }},
		{"duplicate package", func(e []testEvent) []testEvent { return append(e, e[0]) }},
		{"cached completion without execution", func(e []testEvent) []testEvent { return e[6:] }},
		{"test without run", func(e []testEvent) []testEvent { e[1].Action = "output"; return e }},
		{"test without package start", func(e []testEvent) []testEvent { return e[1:] }},
		{"unexpected test", func(e []testEvent) []testEvent { e[1].Test = "TestPrivate"; return e }},
		{"unexpected package", func(e []testEvent) []testEvent { e[1].Package = "PRIVATE_PACKAGE"; return e }},
		{"unexpected executable", func(e []testEvent) []testEvent {
			e[2].Output = strings.ReplaceAll(e[2].Output, "zenon-spv", "PRIVATE_PATH")
			return e
		}},
		{"invalid digest", func(e []testEvent) []testEvent {
			e[2].Output = strings.ReplaceAll(e[2].Output, strings.Repeat("a", 64), "PRIVATE_PATH")
			return e
		}},
		{"invalid record", func(e []testEvent) []testEvent { e[2].Output = binaryMarker + "{PRIVATE}"; return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := collectEvents(t, tc.mutate(sampleEvents()))
			if err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("unexpected execution accepted or private input echoed")
			}
		})
	}
}

func TestReportDropsRawDiagnosticsAndDynamicSubtestNames(t *testing.T) {
	events := sampleEvents()
	events[3].Test, events[4].Test = "TestExample/PRIVATE_PATH", "TestExample/PRIVATE_PATH"
	events = append(events[:3], append([]testEvent{{Action: "output", Package: events[1].Package,
		Test: "TestExample", Output: "PRIVATE_PATH PRIVATE_ENDPOINT PRIVATE_CREDENTIAL"}}, events[3:]...)...)
	c, err := collectEvents(t, events)
	if err != nil || c.finish(true) != "passed" {
		t.Fatal("diagnostic output changed test accounting")
	}
	raw, err := json.Marshal(c.cases)
	if err != nil || bytes.Contains(raw, []byte("PRIVATE")) || c.cases[0].Passed != 1 {
		t.Fatal("report disclosed private diagnostics or lost child accounting")
	}
}

func TestReportRejectsInvalidAndOversizedStreams(t *testing.T) {
	for _, input := range []io.Reader{strings.NewReader("PRIVATE_NOT_JSON\n"), strings.NewReader(strings.Repeat(" ", 1<<20))} {
		c := newCollector(sampleManifest())
		if err := c.read(input); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid stream accepted or disclosed")
		}
	}
}
