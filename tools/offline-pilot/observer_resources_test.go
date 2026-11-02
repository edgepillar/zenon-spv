package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func observerFixture(workload string, round int) observerGroup {
	_, capacity, concurrency := observerGrid(workload)
	exit, peak := int64(0), uint64(4096)
	peakSource := "process_rusage"
	if runtime.GOOS == "windows" {
		peakSource = "windows_peak_working_set"
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		peakSource = "unavailable"
	}
	g := observerGroup{Workload: workload, Round: round, Capacity: capacity, Concurrency: concurrency, Targets: 16,
		StateBytes: 1000, BundleBytes: 2000, ExpectationsBytes: 3000, ElapsedNS: int64(round + 1)}
	for slot := 0; slot < concurrency; slot++ {
		p := observerSlot{Slot: slot, ActualExit: 0, ElapsedNS: int64(round*100 + slot + 1), Peak: &peak, PeakSource: peakSource,
			ObserverNS: 10, Targets: 16, Verifier: observerChild{ExitCode: &exit, ElapsedNS: 2, StdoutBytes: 128},
			Consumer: observerChild{ExitCode: &exit, ElapsedNS: 3, StdoutBytes: 32}}
		if peakSource == "unavailable" {
			p.Peak = nil
		}
		g.Observations = append(g.Observations, p)
	}
	return g
}

func observerJSON(t testing.TB, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func observerEvents(t testing.TB, split bool) []testEvent {
	t.Helper()
	pkg := modulePath + "/internal/conformance"
	events := []testEvent{{Action: "start", Package: pkg}, {Action: "run", Package: pkg, Test: observerResourceRoot}}
	for _, workload := range observerWorkloads {
		name := observerResourceRoot + "/" + workload
		events = append(events, testEvent{Action: "run", Package: pkg, Test: name})
		for round := 0; round < observerRounds; round++ {
			line := "    fixture.go:1: " + observerResourceMarker + observerJSON(t, observerFixture(workload, round)) + "\n"
			if split {
				cut := strings.Index(line, observerResourceMarker) + len(observerResourceMarker) + 50
				events = append(events, testEvent{Action: "output", Package: pkg, Test: name, Output: line[:cut]})
				line = line[cut:]
			}
			events = append(events, testEvent{Action: "output", Package: pkg, Test: name, Output: line})
		}
		events = append(events, testEvent{Action: "pass", Package: pkg, Test: name})
	}
	return append(events, testEvent{Action: "pass", Package: pkg, Test: observerResourceRoot}, testEvent{Action: "pass", Package: pkg})
}

func collectObserverEvents(t testing.TB, events []testEvent) (*suiteCollector, error) {
	t.Helper()
	var b bytes.Buffer
	for _, e := range events {
		if json.NewEncoder(&b).Encode(e) != nil {
			t.Fatal("fixture encoding")
		}
	}
	c, err := newSuiteCollector(newCollector(nil), []string{modulePath + "/internal/conformance"})
	if err != nil {
		t.Fatal(err)
	}
	return c, c.read(&b)
}

func TestObserverSuiteResourcesCompleteAndSplit(t *testing.T) {
	for _, split := range []bool{false, true} {
		c, err := collectObserverEvents(t, observerEvents(t, split))
		if err != nil || c.finish(true) != "passed" {
			t.Fatal("complete observations refused", err)
		}
		r := c.observer.snapshot()
		if r.Status != "complete" || len(r.Records) != 84 || len(r.Failures) != 0 {
			t.Fatal("lost complete groups")
		}
		if !reflect.DeepEqual(r.Records[83], observerFixture("K4096_T16_C4", 20)) {
			t.Fatal("round/slot order or numeric observation changed")
		}
		count := 0
		for _, g := range r.Records {
			count += len(g.Observations)
		}
		if count != 210 {
			t.Fatal("lost outer-process observation")
		}
		if c.finish(false) == "passed" {
			t.Fatal("resource records overrode actual process failure")
		}
	}
}

func TestObserverSuiteResourcesStrictRecords(t *testing.T) {
	raw := observerJSON(t, observerFixture("K256_T16_C1", 0))
	changes := map[string]string{
		"unknown":     strings.Replace(raw, "{", "{\"PRIVATE_PATH\":1,", 1),
		"alias":       strings.Replace(raw, "\"targets\"", "\"TARGETS\"", 1),
		"duplicate":   strings.Replace(raw, "{", "{\"targets\":16,", 1),
		"null":        strings.Replace(raw, "\"targets\":16", "\"targets\":null", 1),
		"slot":        strings.Replace(raw, "\"slot\":0", "\"slot\":1", 1),
		"float":       strings.Replace(raw, "\"round\":0", "\"round\":0.0", 1),
		"child":       strings.Replace(raw, "\"exit_code\":0", "\"exit_code\":null", 1),
		"extra-child": strings.Replace(raw, "\"exit_code\":0", "\"exit_code\":0,\"PRIVATE\":0", 1),
		"negative":    strings.Replace(raw, "\"group_elapsed_ns\":1", "\"group_elapsed_ns\":-1", 1),
		"trailing":    raw + " {}", "invalid-utf8": raw + string([]byte{0xff}), "large": strings.Repeat(" ", observerRecordLimit+1),
	}
	for name, value := range changes {
		t.Run(name, func(t *testing.T) {
			if _, ok := parseObserverGroup([]byte(value), runtime.GOOS); ok {
				t.Fatal("ambiguous or unsupported record accepted")
			}
		})
	}
	for _, platform := range []string{"linux", "darwin", "windows"} {
		g := observerFixture("K256_T16_C1", 0)
		peak := uint64(4096)
		g.Observations[0].Peak = &peak
		g.Observations[0].PeakSource = "process_rusage"
		if platform == "windows" {
			g.Observations[0].PeakSource = "windows_peak_working_set"
		}
		if _, ok := parseObserverGroup([]byte(observerJSON(t, g)), platform); !ok {
			t.Fatal("native accounting source refused")
		}
		g.Observations[0].PeakSource = "PRIVATE_COUNTER"
		if _, ok := parseObserverGroup([]byte(observerJSON(t, g)), platform); ok {
			t.Fatal("arbitrary counter source retained")
		}
	}
}

func TestObserverSuiteResourcesOrderingLimitsAndPrivacy(t *testing.T) {
	for _, mode := range []string{"duplicate", "missing", "reordered", "truncated", "wrong-workload", "skipped-workload", "total-cap"} {
		t.Run(mode, func(t *testing.T) {
			e := observerEvents(t, false)
			switch mode {
			case "duplicate":
				e = append(e[:4], append([]testEvent{e[3]}, e[4:]...)...)
			case "missing":
				e = append(e[:3], e[4:]...)
			case "reordered":
				e[3], e[4] = e[4], e[3]
			case "truncated":
				e[3].Output = strings.TrimSuffix(e[3].Output, "\n")
			case "wrong-workload":
				e[3].Output = strings.ReplaceAll(e[3].Output, "K256_T16_C1", "K256_T16_C4")
			case "skipped-workload":
				for i := range e {
					if e[i].Action == "pass" && e[i].Test == observerResourceRoot+"/K256_T16_C1" {
						e[i].Action = "skip"
					}
				}
			case "total-cap":
				for i := range e {
					if e[i].Action == "output" {
						e[i].Output = strings.Replace(e[i].Output, "{", "{"+strings.Repeat(" ", 4000), 1)
					}
				}
			}
			c, err := collectObserverEvents(t, e)
			if err == nil || c.finish(false) == "passed" {
				t.Fatal("incomplete/over-budget observations appeared complete")
			}
			raw := observerJSON(t, c.observer.snapshot())
			if strings.Contains(raw, "PRIVATE") {
				t.Fatal("private diagnostic escaped")
			}
		})
	}
	c := &observerResourceCollector{}
	if c.snapshot().Status != "missing" {
		t.Fatal("missing measurements invented")
	}
	if err := c.event(testEvent{Action: "output", Package: modulePath + "/internal/other", Test: "TestOther", Output: observerResourceMarker + "PRIVATE_PATH"}); err != nil || c.snapshot().Status != "missing" {
		t.Fatal("foreign diagnostic became measurement")
	}
}

func TestObserverSuiteResourcesFailurePreserved(t *testing.T) {
	pkg := modulePath + "/internal/conformance"
	name := observerResourceRoot + "/K256_T16_C1"
	f := observerFailure{Round: 1, Slot: 0, ActualExit: -1, HelperFailure: true, Category: "unknown"}
	e := []testEvent{{Action: "start", Package: pkg}, {Action: "run", Package: pkg, Test: observerResourceRoot}, {Action: "run", Package: pkg, Test: name},
		{Action: "output", Package: pkg, Test: name, Output: observerResourceMarker + observerJSON(t, observerFixture("K256_T16_C1", 0)) + "\n"},
		{Action: "output", Package: pkg, Test: name, Output: observerFailureMarker + observerJSON(t, f) + "\n"},
		{Action: "fail", Package: pkg, Test: name}, {Action: "fail", Package: pkg, Test: observerResourceRoot}, {Action: "fail", Package: pkg}}
	c, err := collectObserverEvents(t, e)
	if err != nil || c.finish(false) != "failed" {
		t.Fatal("actual failure lost", err)
	}
	r := c.observer.snapshot()
	if r.Status != "failed" || len(r.Records) != 1 || len(r.Failures) != 1 || !reflect.DeepEqual(r.Failures[0].Failure, f) {
		t.Fatal("partial observations/failure context lost")
	}
	for _, category := range []string{"PRIVATE_PATH", "none cancelled", "unknown/PRIVATE"} {
		f.Category = category
		if _, ok := parseObserverFailure([]byte(observerJSON(t, f))); ok {
			t.Fatal("arbitrary failure category retained")
		}
	}
}
