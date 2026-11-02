package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	observerResourceRoot   = "TestCompiledBlockObserverResources"
	observerResourceMarker = "offline-observer-workflow-resource "
	observerFailureMarker  = "offline-observer-workflow-resource-failure "
	observerRecordLimit    = 16 << 10
	observerTotalLimit     = 256 << 10
	observerRounds         = 21
	observerGroups         = 84
	observerDurationLimit  = 86400 * 1_000_000_000
)

var observerWorkloads = []string{"K256_T16_C1", "K256_T16_C4", "K4096_T16_C1", "K4096_T16_C4"}

type observerIncomplete struct {
	StdoutEOF        bool `json:"stdout_eof"`
	StderrEOF        bool `json:"stderr_eof"`
	WaitDelayExpired bool `json:"wait_delay_expired"`
}

type observerChild struct {
	ExitCode    *int64              `json:"exit_code"`
	ElapsedNS   int64               `json:"elapsed_ns"`
	StdoutBytes int64               `json:"stdout_bytes"`
	StderrBytes int64               `json:"stderr_bytes"`
	Incomplete  *observerIncomplete `json:"incomplete_output,omitempty"`
}

type observerSlot struct {
	Slot       int           `json:"slot"`
	ActualExit int64         `json:"actual_exit"`
	ElapsedNS  int64         `json:"elapsed_ns"`
	Peak       *uint64       `json:"waited_peak_bytes"`
	PeakSource string        `json:"waited_peak_source"`
	ObserverNS int64         `json:"observer_elapsed_ns"`
	Targets    int           `json:"checked_targets"`
	Verifier   observerChild `json:"verifier"`
	Consumer   observerChild `json:"consumer"`
}

type observerGroup struct {
	Workload          string         `json:"workload"`
	Round             int            `json:"round"`
	Capacity          int            `json:"retained_headers"`
	Targets           int            `json:"targets"`
	Concurrency       int            `json:"concurrency"`
	StateBytes        int64          `json:"state_bytes"`
	BundleBytes       int64          `json:"bundle_bytes"`
	ExpectationsBytes int64          `json:"expectations_bytes"`
	ElapsedNS         int64          `json:"group_elapsed_ns"`
	Observations      []observerSlot `json:"observations"`
}

type observerFailure struct {
	Round            int           `json:"round"`
	Slot             int           `json:"slot"`
	ActualExit       int64         `json:"actual_exit"`
	HelperFailure    bool          `json:"helper_failure"`
	StdoutBytes      int64         `json:"stdout_bytes"`
	StderrBytes      int64         `json:"stderr_bytes"`
	SummaryAvailable bool          `json:"summary_available"`
	Category         string        `json:"category"`
	Verifier         observerChild `json:"verifier"`
	Consumer         observerChild `json:"consumer"`
}

type observerFailedGroup struct {
	Workload string          `json:"workload"`
	Failure  observerFailure `json:"failure"`
}

type suiteObserverResources struct {
	Format   string                `json:"format"`
	Status   string                `json:"status"`
	Records  []observerGroup       `json:"records"`
	Failures []observerFailedGroup `json:"failures"`
}

type observerResourceCollector struct {
	root     string
	counts   [4]int
	failed   [4]bool
	passed   [4]bool
	last     int
	bytes    int
	fragment map[string]string
	records  []observerGroup
	failures []observerFailedGroup
}

// Exact, integer-only source-owned objects. Unknown keys, aliases, duplicates,
// missing fields and forbidden nulls never become public observations.
func observerObject(raw []byte, fields map[string]any, optional, nullable string) bool {
	if !utf8.Valid(raw) || len(raw) > observerRecordLimit {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, len(fields))
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		target, known := fields[name]
		if err != nil || !ok || !known || seen[name] {
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || name != nullable && bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, target) != nil {
			return false
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return false
	}
	for name := range fields {
		if !seen[name] && name != optional {
			return false
		}
	}
	return true
}

func observerNumber(value, max int64) bool { return value >= 0 && value <= max }
func observerExit(value int64) bool        { return value >= -1<<31 && value <= 1<<32-1 }

func parseObserverChild(raw json.RawMessage, success bool, outputLimit int64) (observerChild, bool) {
	var c observerChild
	var incomplete json.RawMessage
	if !observerObject(raw, map[string]any{"exit_code": &c.ExitCode, "elapsed_ns": &c.ElapsedNS,
		"stdout_bytes": &c.StdoutBytes, "stderr_bytes": &c.StderrBytes, "incomplete_output": &incomplete}, "incomplete_output", "exit_code") ||
		!observerNumber(c.ElapsedNS, observerDurationLimit) || !observerNumber(c.StdoutBytes, 64<<20) || !observerNumber(c.StderrBytes, 64<<20) || c.ExitCode != nil && !observerExit(*c.ExitCode) {
		return observerChild{}, false
	}
	if incomplete != nil {
		c.Incomplete = &observerIncomplete{}
		if !observerObject(incomplete, map[string]any{"stdout_eof": &c.Incomplete.StdoutEOF, "stderr_eof": &c.Incomplete.StderrEOF, "wait_delay_expired": &c.Incomplete.WaitDelayExpired}, "", "") {
			return observerChild{}, false
		}
	}
	if success && (c.ExitCode == nil || *c.ExitCode != 0 || c.ElapsedNS == 0 || c.StdoutBytes == 0 || c.StdoutBytes > outputLimit || c.StderrBytes != 0 || c.Incomplete != nil) {
		return observerChild{}, false
	}
	return c, true
}

func observerGrid(workload string) (index, capacity, concurrency int) {
	for i, name := range observerWorkloads {
		if name == workload {
			return i, []int{256, 256, 4096, 4096}[i], []int{1, 4, 1, 4}[i]
		}
	}
	return -1, 0, 0
}

func parseObserverGroup(raw []byte, platform string) (observerGroup, bool) {
	var g observerGroup
	var points []json.RawMessage
	if !observerObject(raw, map[string]any{"workload": &g.Workload, "round": &g.Round, "retained_headers": &g.Capacity,
		"targets": &g.Targets, "concurrency": &g.Concurrency, "state_bytes": &g.StateBytes, "bundle_bytes": &g.BundleBytes,
		"expectations_bytes": &g.ExpectationsBytes, "group_elapsed_ns": &g.ElapsedNS, "observations": &points}, "", "") {
		return g, false
	}
	index, capacity, concurrency := observerGrid(g.Workload)
	if index < 0 || g.Round < 0 || g.Round >= observerRounds || g.Capacity != capacity || g.Targets != 16 || g.Concurrency != concurrency || len(points) != concurrency ||
		g.StateBytes <= 0 || g.StateBytes > 64<<20 || g.BundleBytes <= 0 || g.BundleBytes > 64<<20 || g.ExpectationsBytes <= 0 || g.ExpectationsBytes > 256<<10 ||
		g.ElapsedNS <= 0 || g.ElapsedNS > observerDurationLimit {
		return g, false
	}
	for i, raw := range points {
		var p observerSlot
		var verifier, consumer json.RawMessage
		if !observerObject(raw, map[string]any{"slot": &p.Slot, "actual_exit": &p.ActualExit, "elapsed_ns": &p.ElapsedNS,
			"waited_peak_bytes": &p.Peak, "waited_peak_source": &p.PeakSource, "observer_elapsed_ns": &p.ObserverNS,
			"checked_targets": &p.Targets, "verifier": &verifier, "consumer": &consumer}, "", "waited_peak_bytes") ||
			p.Slot != i || p.ActualExit != 0 || p.ElapsedNS <= 0 || p.ElapsedNS > observerDurationLimit || p.ObserverNS <= 0 || p.ObserverNS > observerDurationLimit || p.Targets != 16 || !validResourceMemory(p.Peak, p.PeakSource, platform) {
			return g, false
		}
		var ok bool
		if p.Verifier, ok = parseObserverChild(verifier, true, 4<<20); !ok {
			return g, false
		}
		if p.Consumer, ok = parseObserverChild(consumer, true, 1024); !ok {
			return g, false
		}
		g.Observations = append(g.Observations, p)
	}
	return g, true
}

func parseObserverFailure(raw []byte) (observerFailure, bool) {
	var f observerFailure
	var verifier, consumer json.RawMessage
	if !observerObject(raw, map[string]any{"round": &f.Round, "slot": &f.Slot, "actual_exit": &f.ActualExit,
		"helper_failure": &f.HelperFailure, "stdout_bytes": &f.StdoutBytes, "stderr_bytes": &f.StderrBytes,
		"summary_available": &f.SummaryAvailable, "category": &f.Category, "verifier": &verifier, "consumer": &consumer}, "", "") ||
		f.Round < 0 || f.Round >= observerRounds || f.Slot < 0 || f.Slot >= 4 || !observerExit(f.ActualExit) || !observerNumber(f.StdoutBytes, 64<<20) || !observerNumber(f.StderrBytes, 64<<20) {
		return f, false
	}
	allowed := " unknown none cancelled input_unavailable binary_mismatch cleanup_failure output_limit timeout process_unavailable process_failure output_incomplete invalid_summary invalid_expectations invalid_report report_mismatch trust_mismatch target_mismatch guarantee_mismatch consumer_failure "
	if !slices.Contains(strings.Fields(allowed), f.Category) {
		return f, false
	}
	var ok bool
	if f.Verifier, ok = parseObserverChild(verifier, false, 0); !ok {
		return f, false
	}
	if f.Consumer, ok = parseObserverChild(consumer, false, 0); !ok {
		return f, false
	}
	return f, true
}

func (c *observerResourceCollector) event(e testEvent) error {
	if e.Package != modulePath+"/internal/conformance" || e.Test != observerResourceRoot && !strings.HasPrefix(e.Test, observerResourceRoot+"/") {
		return nil
	}
	invalid := errors.New("invalid observer resource observation")
	if e.Test == observerResourceRoot {
		if e.Action == "run" {
			c.root = "running"
		}
		if e.Action == "pass" || e.Action == "fail" || e.Action == "skip" {
			c.root = e.Action
			if len(c.fragment) != 0 || e.Action == "pass" && (len(c.records) != observerGroups || len(c.failures) != 0 || c.passed != [4]bool{true, true, true, true}) {
				return invalid
			}
		}
	}
	if e.Action != "output" {
		if _, pending := c.fragment[e.Test]; pending && (e.Action == "pass" || e.Action == "fail" || e.Action == "skip") {
			return invalid
		}
		if index, _, _ := observerGrid(strings.TrimPrefix(e.Test, observerResourceRoot+"/")); index >= 0 && e.Action == "pass" {
			if c.counts[index] != observerRounds || c.failed[index] {
				return invalid
			}
			c.passed[index] = true
		}
		return nil
	}
	raw, pending := c.fragment[e.Test]
	if pending {
		raw += e.Output
		delete(c.fragment, e.Test)
	} else {
		if _, value, ok := strings.Cut(e.Output, observerResourceMarker); ok {
			raw = observerResourceMarker + value
		} else if _, value, ok := strings.Cut(e.Output, observerFailureMarker); ok {
			raw = observerFailureMarker + value
		} else {
			return nil
		}
	}
	workload := strings.TrimPrefix(e.Test, observerResourceRoot+"/")
	index, _, concurrency := observerGrid(workload)
	if c.root != "running" || index < 0 || index < c.last || c.failed[index] || len(raw) > observerRecordLimit || c.bytes+len(raw) > observerTotalLimit {
		return invalid
	}
	if !strings.HasSuffix(raw, "\n") {
		if c.fragment == nil {
			c.fragment = make(map[string]string)
		}
		c.fragment[e.Test] = raw
		return nil
	}
	c.last = index
	c.bytes += len(raw)
	if value, ok := strings.CutPrefix(raw, observerResourceMarker); ok {
		g, valid := parseObserverGroup([]byte(value), runtime.GOOS)
		if !valid || g.Workload != workload || g.Round != c.counts[index] || len(c.records) >= observerGroups {
			return invalid
		}
		c.counts[index]++
		c.records = append(c.records, g)
		return nil
	}
	value := strings.TrimPrefix(raw, observerFailureMarker)
	f, valid := parseObserverFailure([]byte(value))
	if !valid || f.Round != c.counts[index] || f.Slot >= concurrency || len(c.failures) >= 4 {
		return invalid
	}
	c.failed[index] = true
	c.failures = append(c.failures, observerFailedGroup{workload, f})
	return nil
}

func (c *observerResourceCollector) snapshot() suiteObserverResources {
	status := "incomplete"
	if c.root == "" {
		status = "missing"
	}
	if c.root == "fail" || len(c.failures) != 0 {
		status = "failed"
	}
	if c.root == "pass" && len(c.records) == observerGroups && len(c.failures) == 0 && len(c.fragment) == 0 && c.passed == [4]bool{true, true, true, true} {
		status = "complete"
	}
	return suiteObserverResources{Format: "zenon-observer-workflow-resources/v1", Status: status,
		Records: append([]observerGroup{}, c.records...), Failures: append([]observerFailedGroup{}, c.failures...)}
}
