package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
)

type binaryRecord struct {
	Command string `json:"command"`
	SHA256  string `json:"sha256"`
}

type caseResult struct {
	scenario
	Status         string                `json:"status"`
	Passed         int                   `json:"passed_subtests"`
	Skipped        int                   `json:"skipped_subtests"`
	Failed         int                   `json:"failed_subtests"`
	Binaries       []binaryRecord        `json:"binaries"`
	Resources      []resourceRecord      `json:"resource_samples,omitempty"`
	QueryResources []queryResourceRecord `json:"query_resource_samples,omitempty"`
}

type testEvent struct {
	Action  string
	Package string
	Test    string
	Output  string
}

type eventCollector struct {
	cases          []caseResult
	active         map[string]bool
	packages       map[string]string
	queryFragments map[string]string
}

func newCollector(manifest []scenario) *eventCollector {
	c := &eventCollector{active: make(map[string]bool), packages: make(map[string]string), queryFragments: make(map[string]string)}
	for _, s := range manifest {
		c.cases = append(c.cases, caseResult{scenario: s, Status: "missing", Binaries: []binaryRecord{}})
		c.packages[modulePath+"/"+s.Package] = "missing"
	}
	return c
}

// Raw test output is deliberately never copied into the report. A bounded
// stream and an explicit manifest prevent truncated/missing execution from
// being confused with a successful test selection.
func (c *eventCollector) read(r io.Reader) error {
	const maxBytes = 32 << 20
	limited := &io.LimitedReader{R: r, N: maxBytes + 1}
	s := bufio.NewScanner(limited)
	s.Buffer(make([]byte, 4096), 1<<20)
	for s.Scan() {
		var e testEvent
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			return errors.New("invalid test event stream")
		}
		if err := c.event(e); err != nil {
			return err
		}
	}
	if s.Err() != nil || limited.N == 0 {
		return errors.New("test event stream exceeded limits or could not be read")
	}
	return nil
}

func (c *eventCollector) event(e testEvent) error {
	if _, expected := c.packages[e.Package]; !expected {
		// Go may report build output for dependencies without executing tests.
		if e.Test != "" {
			return errors.New("unexpected test package")
		}
		return nil
	}
	if e.Test == "" {
		switch e.Action {
		case "start":
			if c.packages[e.Package] != "missing" {
				return errors.New("duplicate package execution")
			}
			c.packages[e.Package] = "running"
		case "pass", "fail", "skip":
			if c.packages[e.Package] != "running" {
				return errors.New("package completion without execution")
			}
			c.packages[e.Package] = e.Action
		}
		return nil
	}
	root, _, nested := strings.Cut(e.Test, "/")
	var result *caseResult
	for i := range c.cases {
		if c.cases[i].Test == root && modulePath+"/"+c.cases[i].Package == e.Package {
			result = &c.cases[i]
			break
		}
	}
	if result == nil {
		return errors.New("unexpected test selection")
	}
	key := e.Package + "/" + e.Test
	switch e.Action {
	case "run":
		if _, seen := c.active[key]; seen || len(c.active) >= 65536 || c.packages[e.Package] != "running" {
			return errors.New("invalid test execution")
		}
		c.active[key] = true
		if !nested {
			result.Status = "running"
		}
	case "pass", "fail", "skip":
		if _, pending := c.queryFragments[key]; pending {
			return errors.New("unfinished query resource record")
		}
		if !c.active[key] {
			return errors.New("test completion without execution")
		}
		c.active[key] = false
		if !nested {
			result.Status = e.Action
		} else {
			switch e.Action {
			case "pass":
				result.Passed++
			case "skip":
				result.Skipped++
			case "fail":
				result.Failed++
			}
		}
	case "output":
		// test2json can split a single long Log line into multiple output events.
		// Reassemble only recognized, bounded query records from the same active
		// workload. Never retain unrelated diagnostics or emit fragment text.
		if fragment, pending := c.queryFragments[key]; pending {
			if !c.active[key] || len(fragment)+len(e.Output) > queryResourceRecordLimit {
				return errors.New("invalid query resource fragment")
			}
			e.Output = queryResourceMarker + fragment + e.Output
			delete(c.queryFragments, key)
		}
		if _, raw, ok := strings.Cut(e.Output, queryResourceMarker); ok {
			if len(raw) > queryResourceRecordLimit {
				return errors.New("invalid query resource record")
			}
			decodeErr := json.NewDecoder(strings.NewReader(raw)).Decode(new(json.RawMessage))
			if (decodeErr == io.ErrUnexpectedEOF || decodeErr == io.EOF) && !strings.HasSuffix(raw, "\n") {
				_, workload := queryResourceWorkloads[strings.TrimPrefix(e.Test, result.Test+"/")]
				if !c.active[key] || result.ID != "compiled_query_consumer_scaling" || !workload {
					return errors.New("invalid query resource fragment")
				}
				c.queryFragments[key] = raw
				return nil
			}
			record, err := parseQueryResource(raw)
			if err != nil || !c.active[key] || result.ID != "compiled_query_consumer_scaling" || e.Test != result.Test+"/"+record.Workload ||
				slices.ContainsFunc(result.QueryResources, func(r queryResourceRecord) bool { return r.Workload == record.Workload }) {
				return errors.New("invalid query resource record")
			}
			result.QueryResources = append(result.QueryResources, record)
		}
		if _, raw, ok := strings.Cut(e.Output, resourceMarker); ok {
			record, err := parseResource(raw)
			if err != nil || !c.active[key] || result.ID != "compiled_content_scaling" || e.Test != result.Test+"/"+record.Workload ||
				slices.ContainsFunc(result.Resources, func(r resourceRecord) bool { return r.Workload == record.Workload }) {
				return errors.New("invalid resource record")
			}
			result.Resources = append(result.Resources, record)
		}
		if _, raw, ok := strings.Cut(e.Output, binaryMarker); ok {
			var record binaryRecord
			if !c.active[key] || json.Unmarshal([]byte(raw), &record) != nil ||
				!slices.Contains(result.Commands, record.Command) || !hexDigest(record.SHA256, 64) {
				return errors.New("invalid executable record")
			}
			if !slices.Contains(result.Binaries, record) {
				result.Binaries = append(result.Binaries, record)
			}
		}
	}
	return nil
}

func (c *eventCollector) finish(processOK bool) string {
	status := "passed"
	for i := range c.cases {
		r := &c.cases[i]
		slices.SortFunc(r.Binaries, func(a, b binaryRecord) int {
			if a.Command != b.Command {
				return strings.Compare(a.Command, b.Command)
			}
			return strings.Compare(a.SHA256, b.SHA256)
		})
		switch r.Status {
		case "pass":
			r.Status = "passed"
			if r.Skipped != 0 {
				r.Status = "passed_with_skips"
			}
			for _, command := range r.Commands {
				if !slices.ContainsFunc(r.Binaries, func(b binaryRecord) bool { return b.Command == command }) {
					r.Status = "incomplete"
				}
			}
			if r.ID == "compiled_content_scaling" && len(r.Resources) != len(resourceWorkloads) {
				r.Status = "incomplete"
			}
			if r.ID == "compiled_query_consumer_scaling" && len(r.QueryResources) != len(queryResourceWorkloads) {
				r.Status = "incomplete"
			}
		case "fail":
			r.Status = "failed"
		case "skip":
			r.Status = "skipped"
		default:
			r.Status = "incomplete"
		}
		if r.Failed != 0 {
			r.Status = "failed"
		}
		if r.Status == "incomplete" || r.Status == "skipped" {
			status = "incomplete"
		} else if r.Status == "passed_with_skips" && status == "passed" {
			status = "passed_with_skips"
		}
	}
	for _, state := range c.packages {
		if state != "pass" {
			status = "incomplete"
		}
	}
	for _, active := range c.active {
		if active {
			status = "incomplete"
		}
	}
	if len(c.queryFragments) != 0 {
		status = "incomplete"
	}
	if !processOK || slices.ContainsFunc(c.cases, func(r caseResult) bool { return r.Status == "failed" }) {
		status = "failed"
	}
	return status
}

func hexDigest(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
