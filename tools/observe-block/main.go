// Command observe-block performs one bounded, read-only block check.
// It supervises reviewed verifier and consumer binaries and can first collect
// proof-only evidence from an explicitly selected RPC through a pinned collector.
// It neither chooses trust inputs nor turns diagnostic matching into finality.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/0x3639/zenon-spv/internal/verify"
)

const (
	maxReportBytes       = 4 << 20
	maxExpectationsBytes = 256 << 10
	maxBinaryBytes       = 128 << 20
	maxSummaryBytes      = 1024
)

type configuration struct {
	verifier, consumer, verifierHash, consumerHash                              string
	command, anchor, profile, schedule, state, bundle, expectations, privateDir string
	pin, window, retention                                                      string
	timeout                                                                     time.Duration
	collection                                                                  collectionConfiguration
}

type observation struct {
	ExitCode    *int64 `json:"exit_code"`
	ElapsedNS   int64  `json:"elapsed_ns"`
	StdoutBytes int64  `json:"stdout_bytes"`
	StderrBytes int64  `json:"stderr_bytes"`
}

type summary struct {
	Version        uint32       `json:"schema_version"`
	Status         string       `json:"status"`
	Category       *string      `json:"category"`
	CheckedTargets int          `json:"checked_targets"`
	ElapsedNS      int64        `json:"elapsed_ns"`
	Verifier       observation  `json:"verifier"`
	Consumer       observation  `json:"consumer"`
	Collector      *observation `json:"collector,omitempty"`
}

type consumption struct {
	Version        uint32  `json:"schema_version"`
	Status         string  `json:"status"`
	Category       *string `json:"category"`
	CheckedTargets int     `json:"checked_targets"`
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, diagnostics io.Writer) int {
	c, ok := parseConfiguration(args)
	if !ok {
		_, _ = fmt.Fprintln(diagnostics, "observe-block: require explicit binaries and hashes, trust inputs, state, expectations, context, window, retention, private directory and either a bundle or complete RPC collection inputs")
		return 64
	}
	r, code := observe(ctx, c)
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
		_, _ = fmt.Fprintln(diagnostics, "observe-block: cannot write result")
		return 70
	}
	return code
}

func parseConfiguration(args []string) (configuration, bool) {
	c := configuration{timeout: 30 * time.Second}
	fs := flag.NewFlagSet("observe-block", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	seen := make(map[string]bool)
	add := func(name string, destination *string) {
		fs.Func(name, "explicit local pilot input", func(value string) error {
			if seen[name] || value == "" {
				return errors.New("duplicate or empty option")
			}
			seen[name], *destination = true, value
			return nil
		})
	}
	for _, option := range []struct {
		name  string
		value *string
	}{
		{"verifier", &c.verifier}, {"consumer", &c.consumer}, {"verifier-sha256", &c.verifierHash}, {"consumer-sha256", &c.consumerHash},
		{"command", &c.command}, {"genesis-config", &c.anchor}, {"protocol-profile", &c.profile}, {"schedule", &c.schedule},
		{"state", &c.state}, {"bundle", &c.bundle}, {"expectations", &c.expectations}, {"private-dir", &c.privateDir},
		{"expect-context", &c.pin}, {"window", &c.window}, {"retain-headers", &c.retention},
		{"collector", &c.collection.binary}, {"collector-sha256", &c.collection.hash}, {"rpc", &c.collection.rpc},
		{"height", &c.collection.height}, {"count", &c.collection.count}, {"commitments", &c.collection.commitments}, {"segments", &c.collection.segments},
		{"momentum-heights", &c.collection.momentumHeights},
	} {
		add(option.name, option.value)
	}
	fs.Func("timeout", "per-child deadline, positive and at most one minute", func(value string) error {
		if seen["timeout"] {
			return errors.New("duplicate option")
		}
		seen["timeout"] = true
		var err error
		c.timeout, err = time.ParseDuration(value)
		return err
	})
	if fs.Parse(args) != nil || fs.NArg() != 0 || c.timeout <= 0 || c.timeout > time.Minute ||
		!slices.Contains([]string{"verify-commitment", "verify-segment"}, c.command) ||
		!slices.Contains([]string{"low", "medium", "high"}, c.window) || !digest(c.pin) || !digest(c.verifierHash) || !digest(c.consumerHash) {
		return c, false
	}
	// Require every input separately; an optional timeout cannot stand in for a
	// missing path. Policy validation shares the verifier's depth/capacity rule.
	for _, name := range []string{"verifier", "consumer", "verifier-sha256", "consumer-sha256", "command", "genesis-config", "protocol-profile", "schedule", "state", "expectations", "private-dir", "expect-context", "window", "retain-headers"} {
		if !seen[name] {
			return c, false
		}
	}
	k, err := strconv.Atoi(c.retention)
	p := verify.PolicyForTier(c.window)
	p.RetainHeaders = k
	return c, err == nil && k > 0 && p.ValidateRetention() == nil && validCollectionSelection(c, seen, k)
}

func digest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, ch := range value {
		digit := ch >= '0' && ch <= '9'
		lowerHex := ch >= 'a' && ch <= 'f'
		if !digit && !lowerHex {
			return false
		}
	}
	return true
}

func observe(ctx context.Context, c configuration) (result summary, code int) {
	started := time.Now()
	result = summary{Version: 1, Status: "not_matched"}
	if c.collection.binary != "" {
		result.Version, result.Collector = 2, &observation{}
	}
	fail := func(category string, status int) (summary, int) {
		result.Status, result.Category, result.CheckedTargets = "not_matched", &category, 0
		return result, status
	}
	defer func() { result.ElapsedNS = time.Since(started).Nanoseconds() }()
	if ctx.Err() != nil {
		return fail("cancelled", 2)
	}
	// Resolve supplied paths without PATH lookup. Regular-file checks and byte
	// pins do not authenticate their source or close replacement races: callers
	// must protect the directory, executables and all selected trust/state files.
	paths := []*string{&c.verifier, &c.consumer, &c.anchor, &c.profile, &c.schedule, &c.state, &c.expectations}
	if c.collection.binary == "" {
		paths = append(paths, &c.bundle)
	} else {
		paths = append(paths, &c.collection.binary)
	}
	for _, path := range paths {
		absolute, ok := regularPath(*path)
		if !ok {
			return fail("input_unavailable", 70)
		}
		*path = absolute
	}
	if !binaryMatches(c.verifier, c.verifierHash) || !binaryMatches(c.consumer, c.consumerHash) ||
		(c.collection.binary != "" && !binaryMatches(c.collection.binary, c.collection.hash)) {
		return fail("binary_mismatch", 2)
	}
	expected, ok := readExpectations(c.expectations)
	if !ok {
		return fail("input_unavailable", 70)
	}
	base, err := filepath.Abs(c.privateDir)
	if err != nil {
		return fail("input_unavailable", 70)
	}
	info, err := os.Lstat(base)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fail("input_unavailable", 70)
	}
	private, err := os.MkdirTemp(base, "block-observation-")
	if err != nil {
		return fail("input_unavailable", 70)
	}
	// Cleanup precedes the final summary. Failure cannot leave a matched result;
	// raw private reports are never printed. Abrupt termination can leave files.
	defer func() {
		if os.RemoveAll(private) != nil {
			result, code = fail("cleanup_failure", 70)
		}
	}()
	expectedPath, reportPath := filepath.Join(private, "expectations.json"), filepath.Join(private, "query.json")
	if os.WriteFile(expectedPath, expected, 0o600) != nil {
		return fail("input_unavailable", 70)
	}
	if c.collection.binary != "" {
		c.bundle = filepath.Join(private, "candidate.json")
		collected := collectBundle(ctx, c, c.bundle)
		// Keep independently owned observation metadata in the summary.
		collectorObservation := collected.observation
		result.Collector = &collectorObservation
		if collected.category != "" {
			return fail(collected.category, collected.code)
		}
	}
	args := []string{c.command, "--json", "--retained-only", "--genesis-config", c.anchor, "--protocol-profile", c.profile,
		"--schedule", c.schedule, "--state", c.state, "--expect-context", c.pin, "--window", c.window, "--retain-headers", c.retention, c.bundle}
	query := runProcess(ctx, c.verifier, args, maxReportBytes, c.timeout)
	result.Verifier = query.observation
	if query.category != "" {
		return fail(query.category, query.code)
	}
	if os.WriteFile(reportPath, query.stdout, 0o600) != nil {
		return fail("input_unavailable", 70)
	}
	consumer := runProcess(ctx, c.consumer, []string{"--report", reportPath, "--expectations", expectedPath, "--verifier-exit-code", "0"}, maxSummaryBytes, c.timeout)
	result.Consumer = consumer.observation
	if consumer.category != "" && (consumer.category != "process_failure" || consumer.ExitCode == nil || *consumer.ExitCode != 2) {
		return fail(consumer.category, consumer.code)
	}
	matched, category, count := matchSummary(consumer.stdout, consumer.ExitCode)
	if !matched {
		return fail(category, 2)
	}
	result.Status, result.Category, result.CheckedTargets = "matched", nil, count
	return result, 0
}

func regularPath(path string) (string, bool) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	info, err := os.Lstat(absolute)
	return absolute, err == nil && info.Mode().IsRegular()
}

func binaryMatches(path, expected string) bool {
	return binaryMatchesWithOpen(path, expected, openPreflightInput)
}

func binaryMatchesWithOpen(path, expected string, openFile func(string) (*os.File, error)) bool {
	f, err := checkedPreflightInput(path, maxBinaryBytes, openFile)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxBinaryBytes+1))
	return err == nil && n <= maxBinaryBytes && hex.EncodeToString(h.Sum(nil)) == expected
}

func readExpectations(path string) ([]byte, bool) {
	return readExpectationsWithOpen(path, openPreflightInput)
}

func readExpectationsWithOpen(path string, openFile func(string) (*os.File, error)) ([]byte, bool) {
	f, err := checkedPreflightInput(path, maxExpectationsBytes, openFile)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxExpectationsBytes+1))
	return raw, err == nil && len(raw) <= maxExpectationsBytes
}

func matchSummary(raw []byte, actual *int64) (bool, string, int) {
	var value consumption
	if json.Unmarshal(raw, &value) != nil {
		return false, "invalid_summary", 0
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) || value.Version != 1 || actual == nil {
		return false, "invalid_summary", 0
	}
	if *actual == 0 && value.Status == "matched" && value.Category == nil && value.CheckedTargets >= 1 && value.CheckedTargets <= 256 {
		return true, "", value.CheckedTargets
	}
	if *actual == 2 && value.Status == "not_matched" && value.Category != nil && value.CheckedTargets == 0 &&
		slices.Contains([]string{"invalid_expectations", "invalid_report", "report_mismatch", "trust_mismatch", "target_mismatch", "guarantee_mismatch", "process_failure"}, *value.Category) {
		return false, *value.Category, 0
	}
	return false, "consumer_failure", 0
}
