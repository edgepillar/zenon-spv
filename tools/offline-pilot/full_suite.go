package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const suiteStreamLimit = 32 << 20

type suitePackage struct {
	Package string `json:"package"`
	Status  string `json:"status"`
}

type suiteCounts struct {
	RootTests int `json:"root_tests"`
	Subtests  int `json:"subtests"`
	Passed    int `json:"passed"`
	Skipped   int `json:"skipped"`
	Failed    int `json:"failed"`
}

// This receipt supplements schema-2 pilot reports. It records the whole root
// module execution without copying raw diagnostics or dynamic test names.
type suiteReceipt struct {
	Format            string                 `json:"format"`
	Status            string                 `json:"status"`
	Error             *string                `json:"error"`
	Source            sourceRecord           `json:"source"`
	InputsUnchanged   bool                   `json:"source_matches_after_run"`
	Race              bool                   `json:"test_parent_race_enabled"`
	Coverage          bool                   `json:"coverage_enabled"`
	PackageTimeout    string                 `json:"package_timeout"`
	OverallTimeout    string                 `json:"overall_timeout"`
	InventoryOK       bool                   `json:"package_inventory_succeeded"`
	ProcessOK         bool                   `json:"test_process_succeeded"`
	StreamComplete    bool                   `json:"stream_complete"`
	StreamBytes       int64                  `json:"stream_bytes"`
	StreamSHA256      string                 `json:"stream_sha256"`
	Packages          []suitePackage         `json:"packages"`
	Tests             suiteCounts            `json:"tests"`
	SelectedScenarios int                    `json:"selected_scenarios"`
	SelectedReportSHA string                 `json:"selected_report_sha256"`
	Timings           suiteTimings           `json:"timings"`
	ObserverResources suiteObserverResources `json:"observer_resources"`
	SourceRoots       *sourceRootEvidence    `json:"source_root_controls,omitempty"`
}

type suiteCollector struct {
	selected    *eventCollector
	packages    map[string]string
	active      map[string]bool
	counts      suiteCounts
	failures    suiteFailures
	timings     suiteTimings
	observer    observerResourceCollector
	sourceRoots *sourceRootCollector
	digest      hash.Hash
	bytes       int64
	complete    bool
}

func fullSuiteArguments(race bool, timeout time.Duration, coverage string) []string {
	args := []string{"test", "-p", "1", "-json", "-count=1", "-timeout=" + timeout.String()}
	if race {
		args = append(args, "-race")
	}
	if coverage != "" {
		args = append(args, "-coverprofile="+coverage)
	}
	return append(args, "./...")
}

// The package list is obtained from an actual offline go list ./... process,
// before the test process, with the same environment and source boundary.
func readSuitePackages(r io.Reader) ([]string, error) {
	limited := &io.LimitedReader{R: r, N: (1 << 20) + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), 4096)
	var packages []string
	for scanner.Scan() {
		name := scanner.Text()
		if !validSuitePackage(name) || slices.Contains(packages, name) || len(packages) >= 1024 {
			return nil, errors.New("invalid suite package inventory")
		}
		packages = append(packages, name)
	}
	if scanner.Err() != nil || limited.N == 0 || len(packages) == 0 {
		return nil, errors.New("incomplete suite package inventory")
	}
	slices.Sort(packages)
	return packages, nil
}

func validSuitePackage(name string) bool {
	if len(name) > 4096 || name != modulePath && !strings.HasPrefix(name, modulePath+"/") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, char := range part {
			if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("-._", char) {
				continue
			}
			return false
		}
	}
	return true
}

func newSuiteCollector(selected *eventCollector, packages []string) (*suiteCollector, error) {
	c := &suiteCollector{selected: selected, packages: make(map[string]string), active: make(map[string]bool), digest: sha256.New()}
	for _, name := range packages {
		if !validSuitePackage(name) || c.packages[name] != "" || len(c.packages) >= 1024 {
			return nil, errors.New("invalid suite package inventory")
		}
		c.packages[name] = "missing"
	}
	for name := range selected.packages {
		if c.packages[name] == "" {
			return nil, errors.New("selected package missing from suite")
		}
	}
	return c, nil
}

func (c *suiteCollector) read(r io.Reader) error {
	limited := &io.LimitedReader{R: r, N: suiteStreamLimit + 1}
	counted := &suiteStreamReader{reader: io.TeeReader(limited, c.digest), count: &c.bytes}
	scanner := bufio.NewScanner(counted)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var event struct {
			testEvent
			Elapsed *float64
		}
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			return errors.New("invalid suite event stream")
		}
		if err := c.event(event.testEvent); err != nil {
			return err
		}
		if err := c.recordTiming(event.testEvent, event.Elapsed); err != nil {
			return err
		}
	}
	if scanner.Err() != nil || limited.N == 0 {
		return errors.New("suite event stream exceeded limits or could not be read")
	}
	c.complete = true
	return nil
}

const suiteTimingLimit = 20
const suiteElapsedLimit = 86400 // A diagnostic bound, not an execution deadline.

type suiteTiming struct {
	Package     string `json:"package"`
	Test        string `json:"test"`
	Status      string `json:"status"`
	Nanoseconds int64  `json:"elapsed_nanoseconds"`
}

type suiteTimings struct {
	Basis         string        `json:"basis"`
	Limit         int           `json:"limit"`
	Completed     int           `json:"completed_roots"`
	Measured      int           `json:"measured_roots"`
	Missing       int           `json:"missing_elapsed"`
	WithheldNames int           `json:"withheld_names"`
	Slowest       []suiteTiming `json:"slowest_roots"`
}

// Only root identifiers produced by Go's test registry may be disclosed. Never
// retain t.Run labels, output, timestamps, paths or an unbounded list of names.
// These observations remain dependent on the trusted test process and source.
func publicSuiteRoot(name string) bool {
	if len(name) == 0 || len(name) > 256 || !strings.HasPrefix(name, "Test") && !strings.HasPrefix(name, "Fuzz") && !strings.HasPrefix(name, "Example") {
		return false
	}
	for _, char := range name {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' {
			continue
		}
		return false
	}
	return true
}

const suiteFailureRootLimit = 20
const suiteFailureOutputLimit = 16 << 10
const suiteFailureMarker = "offline-pilot-suite-failures "

type suiteFailedRoot struct {
	Package string `json:"package"`
	Test    string `json:"test"`
}

type suiteFailures struct {
	Observed int
	Withheld int
	Roots    []suiteFailedRoot
}

func compareSuiteFailedRoot(a, b suiteFailedRoot) int {
	if order := strings.Compare(a.Package, b.Package); order != 0 {
		return order
	}
	return strings.Compare(a.Test, b.Test)
}

// Record only validated terminal root events, never output or t.Run labels.
// The source-pinned Go process remains trusted, as it is for root timings.
func (c *suiteCollector) recordFailure(e testEvent) {
	if e.Action != "fail" || e.Test == "" || strings.Contains(e.Test, "/") {
		return
	}
	c.failures.Observed++
	if len(e.Package) > 256 || !publicSuiteRoot(e.Test) {
		c.failures.Withheld++
		return
	}
	c.failures.Roots = append(c.failures.Roots, suiteFailedRoot{e.Package, e.Test})
	slices.SortFunc(c.failures.Roots, compareSuiteFailedRoot)
	c.failures.Roots = c.failures.Roots[:min(len(c.failures.Roots), suiteFailureRootLimit)]
}

// Failure diagnostics are a bounded, optional log supplement. They do not
// change either receipt schema or turn a partial stream into complete evidence.
func writeSuiteFailures(w io.Writer, enabled bool, c *suiteCollector, status string, processOK bool, reportDigest [sha256.Size]byte) error {
	if !enabled || status == "passed" || status == "passed_with_skips" {
		return nil
	}
	if status != "failed" && status != "incomplete" {
		return errors.New("invalid suite diagnostic status")
	}
	value := struct {
		Format            string            `json:"format"`
		Status            string            `json:"status"`
		ProcessOK         bool              `json:"test_process_succeeded"`
		StreamComplete    bool              `json:"stream_complete"`
		StreamBytes       int64             `json:"stream_bytes"`
		StreamSHA256      string            `json:"stream_sha256"`
		SelectedReportSHA string            `json:"selected_report_sha256"`
		Limit             int               `json:"limit"`
		Observed          int               `json:"observed_failed_roots"`
		Withheld          int               `json:"withheld_names"`
		Omitted           int               `json:"omitted_roots"`
		Roots             []suiteFailedRoot `json:"roots"`
	}{Format: "zenon-root-suite-failures/v1", Status: status, ProcessOK: processOK,
		SelectedReportSHA: hex.EncodeToString(reportDigest[:]), Limit: suiteFailureRootLimit, Roots: []suiteFailedRoot{}}
	if c != nil {
		value.StreamComplete, value.StreamBytes = c.complete, c.bytes
		value.StreamSHA256 = hex.EncodeToString(c.digest.Sum(nil))
		value.Observed, value.Withheld = c.failures.Observed, c.failures.Withheld
		value.Roots = c.failures.Roots
		if value.Roots == nil {
			value.Roots = []suiteFailedRoot{}
		}
		value.Omitted = value.Observed - value.Withheld - len(value.Roots)
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+len(suiteFailureMarker)+1 > suiteFailureOutputLimit {
		return errors.New("suite failure diagnostics exceeded limits")
	}
	raw = append(append([]byte(suiteFailureMarker), raw...), '\n')
	n, err := w.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	return err
}

func writeFullSuiteReport(stdout, stderr io.Writer, raw []byte, code int, c *suiteCollector, enabled, processOK bool, status string) int {
	if err := writeSuiteFailures(stderr, enabled, c, status, processOK, sha256.Sum256(raw)); err != nil {
		code = 70
	}
	// Preserve the selected report even if the optional diagnostic sink fails.
	return writeReport(stdout, stderr, raw, code)
}

func compareSuiteTiming(a, b suiteTiming) int {
	if a.Nanoseconds > b.Nanoseconds {
		return -1
	}
	if a.Nanoseconds < b.Nanoseconds {
		return 1
	}
	if order := strings.Compare(a.Package, b.Package); order != 0 {
		return order
	}
	return strings.Compare(a.Test, b.Test)
}

func (c *suiteCollector) recordTiming(e testEvent, elapsed *float64) error {
	if e.Test == "" || strings.Contains(e.Test, "/") || e.Action != "pass" && e.Action != "fail" && e.Action != "skip" {
		return nil
	}
	if elapsed != nil && (math.IsNaN(*elapsed) || math.IsInf(*elapsed, 0) || *elapsed < 0 || *elapsed > suiteElapsedLimit) {
		return errors.New("invalid suite root elapsed time")
	}
	c.timings.Completed++
	if !publicSuiteRoot(e.Test) {
		c.timings.WithheldNames++
	} else if elapsed == nil {
		c.timings.Missing++
	} else {
		c.timings.Measured++
		// Preserve the existing integer-only metadata grammar. This unit
		// conversion adds no precision to Go's observed Elapsed seconds.
		nanoseconds := int64(math.Round(*elapsed * float64(time.Second)))
		c.timings.Slowest = append(c.timings.Slowest, suiteTiming{e.Package, e.Test, e.Action, nanoseconds})
		slices.SortFunc(c.timings.Slowest, compareSuiteTiming)
		c.timings.Slowest = c.timings.Slowest[:min(len(c.timings.Slowest), suiteTimingLimit)]
	}
	return nil
}

func (c *suiteCollector) timingSnapshot() suiteTimings {
	value := c.timings
	value.Basis, value.Limit = "go_test_elapsed_nanoseconds", suiteTimingLimit
	value.Slowest = append([]suiteTiming{}, value.Slowest...)
	return value
}

type suiteStreamReader struct {
	reader io.Reader
	count  *int64
}

func (r *suiteStreamReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	*r.count += int64(n)
	return n, err
}

func (c *suiteCollector) event(e testEvent) error {
	state, expected := c.packages[e.Package]
	if !expected {
		// Dependencies may emit build diagnostics without executing tests.
		if e.Test == "" && (e.Action == "output" || e.Action == "build-output") {
			return nil
		}
		return errors.New("unexpected suite package")
	}
	if e.Test == "" {
		switch e.Action {
		case "start":
			if state != "missing" {
				return errors.New("duplicate suite package execution")
			}
			c.packages[e.Package] = "running"
		case "pass", "fail", "skip":
			if state != "running" {
				return errors.New("suite package completion without execution")
			}
			for key, active := range c.active {
				if active && strings.HasPrefix(key, e.Package+"\x00") {
					return errors.New("unfinished suite package test")
				}
			}
			c.packages[e.Package] = e.Action
		case "output", "build-output":
		default:
			return errors.New("unexpected suite package action")
		}
		if _, selected := c.selected.packages[e.Package]; selected {
			return c.selected.event(e)
		}
		return nil
	}
	if state != "running" || len(e.Test) > 4096 {
		return errors.New("invalid suite test execution")
	}
	key := e.Package + "\x00" + e.Test
	switch e.Action {
	case "run":
		if _, seen := c.active[key]; seen || len(c.active) >= 65536 {
			return errors.New("duplicate or excessive suite test execution")
		}
		if strings.Contains(e.Test, "/") {
			// One t.Run label can itself contain slashes. Only an actually
			// executed ancestor must be active; synthetic path components are
			// not additional test executions. Paused parents remain active.
			parent := e.Test
			for {
				separator := strings.LastIndexByte(parent, '/')
				if separator < 0 {
					return errors.New("suite subtest without active parent")
				}
				parent = parent[:separator]
				if c.active[e.Package+"\x00"+parent] {
					break
				}
			}
			c.counts.Subtests++
		} else {
			c.counts.RootTests++
		}
		c.active[key] = true
	case "pass", "fail", "skip":
		if !c.active[key] {
			return errors.New("suite test completion without execution")
		}
		c.active[key] = false
		switch e.Action {
		case "pass":
			c.counts.Passed++
		case "skip":
			c.counts.Skipped++
		case "fail":
			c.counts.Failed++
		}
	case "pause", "cont", "output":
		if !c.active[key] {
			return errors.New("suite output without active test")
		}
	default:
		return errors.New("unexpected suite test action")
	}
	root, _, _ := strings.Cut(e.Test, "/")
	c.recordFailure(e)
	if err := c.observer.event(e); err != nil {
		return err
	}
	if err := c.sourceRoots.event(e); err != nil {
		return err
	}
	if slices.ContainsFunc(c.selected.cases, func(result caseResult) bool {
		return result.Test == root && modulePath+"/"+result.Package == e.Package
	}) {
		return c.selected.event(e)
	}
	return nil
}

func (c *suiteCollector) finish(processOK bool) string {
	if !processOK || c.counts.Failed != 0 {
		return "failed"
	}
	if !c.complete || len(c.packages) == 0 || c.counts.RootTests == 0 {
		return "incomplete"
	}
	if !c.sourceRoots.complete() {
		return "incomplete"
	}
	for _, state := range c.packages {
		if state == "fail" {
			return "failed"
		}
		if state != "pass" && state != "skip" {
			return "incomplete"
		}
	}
	for _, active := range c.active {
		if active {
			return "incomplete"
		}
	}
	return "passed"
}

func (c *suiteCollector) snapshot() ([]suitePackage, string) {
	packages := make([]suitePackage, 0, len(c.packages))
	for name, status := range c.packages {
		packages = append(packages, suitePackage{name, status})
	}
	slices.SortFunc(packages, func(a, b suitePackage) int { return strings.Compare(a.Package, b.Package) })
	return packages, hex.EncodeToString(c.digest.Sum(nil))
}

func openSuiteReceipt(path, exportDir string) (*os.File, error) {
	root, err := os.Getwd()
	if err != nil || path == "" || len(path) > 4096 || !filepath.IsAbs(path) || !outsideDirectory(root, path) || exportDir != "" && !outsideDirectory(exportDir, path) {
		return nil, errors.New("invalid suite receipt destination")
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

func outsideDirectory(root, path string) bool {
	// Resolve the existing parent so a directory alias cannot move the receipt
	// into the source or nine-member candidate payload. Never overwrite a file.
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return false
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(resolvedRoot, filepath.Join(parent, filepath.Base(path)))
	return err == nil && (relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func writeSuiteReceipt(file *os.File, value suiteReceipt) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err == nil {
		var written int
		raw = append(raw, '\n')
		written, err = file.Write(raw)
		if err == nil && written != len(raw) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}
