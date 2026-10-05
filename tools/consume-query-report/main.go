// Command consume-query-report is a reference consumer of trusted, local,
// retained-only query diagnostics. It does not authenticate reports or execute
// the verifier. Expectations and the actual verifier process status are inputs.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
)

const (
	maxReportBytes       = 4 << 20
	maxExpectationsBytes = 256 << 10
	maxTargets           = 256
)

type consumption struct {
	Version        uint32  `json:"schema_version"`
	Status         string  `json:"status"`
	Category       *string `json:"category"`
	CheckedTargets int     `json:"checked_targets"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, diagnostics io.Writer) int {
	fs := flag.NewFlagSet("consume-query-report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var reportPath, expectationsPath string
	var processExit int64
	provided := make(map[string]bool)
	// Presence alone cannot distinguish a supplied failure status from one
	// overwritten by a later zero. Refuse every repeated selection, including
	// identical values and mixed flag spellings, before reading either file.
	once := func(name, usage string, set func(string) error) {
		fs.Func(name, usage, func(value string) error {
			if provided[name] {
				return errors.New("duplicate option")
			}
			provided[name] = true
			return set(value)
		})
	}
	once("report", "private verifier JSON report", func(value string) error {
		reportPath = value
		return nil
	})
	once("expectations", "independently selected expectations", func(value string) error {
		expectationsPath = value
		return nil
	})
	once("verifier-exit-code", "actual verifier process exit status", func(value string) error {
		var err error
		processExit, err = strconv.ParseInt(value, 0, 64)
		return err
	})
	parseErr := fs.Parse(args)
	if parseErr != nil || fs.NArg() != 0 || reportPath == "" || expectationsPath == "" || !provided["verifier-exit-code"] {
		_, _ = fmt.Fprintln(diagnostics, "consume-query-report: require --report, --expectations and --verifier-exit-code")
		return 64
	}
	if processExit != 0 {
		return writeConsumption(stdout, diagnostics, "process_failure", 0, 2)
	}
	expectedRaw, err := readInput(expectationsPath, maxExpectationsBytes)
	if err != nil {
		return writeConsumption(stdout, diagnostics, "input_unavailable", 0, 70)
	}
	var expected expectations
	if !decodeExact(expectedRaw, &expected) || !validExpectations(expected) {
		return writeConsumption(stdout, diagnostics, "invalid_expectations", 0, 2)
	}
	reportRaw, err := readInput(reportPath, maxReportBytes)
	if err != nil {
		return writeConsumption(stdout, diagnostics, "input_unavailable", 0, 70)
	}
	var report queryReport
	if !decodeExact(reportRaw, &report) || !validReport(report) {
		return writeConsumption(stdout, diagnostics, "invalid_report", 0, 2)
	}
	if category := matchReport(report, expected); category != "" {
		return writeConsumption(stdout, diagnostics, category, 0, 2)
	}
	return writeConsumption(stdout, diagnostics, "", len(expected.Targets), 0)
}

// Inputs must be regular files. A private, stable report path remains a caller
// responsibility; these checks do not authenticate files or directory owners.
func readInput(path string, limit int64) ([]byte, error) {
	return readInputWithOpen(path, limit, openReadOnlyInput)
}

// Check the pathname before opening and the descriptor before reading. The
// callback lets tests replace the selected path at the actual open boundary
// without changing process-wide behavior.
func readInputWithOpen(path string, limit int64, openFile func(string) (*os.File, error)) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, os.ErrInvalid
	}
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, os.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, os.ErrInvalid
	}
	return raw, nil
}

func writeConsumption(stdout, diagnostics io.Writer, category string, count, code int) int {
	r := consumption{Version: 1, Status: "matched", CheckedTargets: count}
	if category != "" {
		r.Status, r.Category = "not_matched", &category
	}
	raw, err := json.Marshal(r)
	if err == nil {
		raw = append(raw, '\n')
		var n int
		n, err = stdout.Write(raw)
		if err == nil && n != len(raw) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(diagnostics, "consume-query-report: cannot write result")
		return 70
	}
	return code
}
