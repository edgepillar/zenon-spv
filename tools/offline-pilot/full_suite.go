package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
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
	Format            string         `json:"format"`
	Status            string         `json:"status"`
	Error             *string        `json:"error"`
	Source            sourceRecord   `json:"source"`
	InputsUnchanged   bool           `json:"source_matches_after_run"`
	Race              bool           `json:"test_parent_race_enabled"`
	Coverage          bool           `json:"coverage_enabled"`
	PackageTimeout    string         `json:"package_timeout"`
	OverallTimeout    string         `json:"overall_timeout"`
	InventoryOK       bool           `json:"package_inventory_succeeded"`
	ProcessOK         bool           `json:"test_process_succeeded"`
	StreamComplete    bool           `json:"stream_complete"`
	StreamBytes       int64          `json:"stream_bytes"`
	StreamSHA256      string         `json:"stream_sha256"`
	Packages          []suitePackage `json:"packages"`
	Tests             suiteCounts    `json:"tests"`
	SelectedScenarios int            `json:"selected_scenarios"`
	SelectedReportSHA string         `json:"selected_report_sha256"`
}

type suiteCollector struct {
	selected *eventCollector
	packages map[string]string
	active   map[string]bool
	counts   suiteCounts
	digest   hash.Hash
	bytes    int64
	complete bool
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
		var event testEvent
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			return errors.New("invalid suite event stream")
		}
		if err := c.event(event); err != nil {
			return err
		}
	}
	if scanner.Err() != nil || limited.N == 0 {
		return errors.New("suite event stream exceeded limits or could not be read")
	}
	c.complete = true
	return nil
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
