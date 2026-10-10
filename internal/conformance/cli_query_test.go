package conformance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Exercise the shipped main functions, process exit status, separate streams,
// and filesystem effects across collection and offline verification. Expected
// hashes come from the pinned node corpus, not from the subprocesses under test.
func TestCompiledCLIQueryWorkflow(t *testing.T) {
	bins := buildQueryCLIs(t)
	c, seed := contractBatchBundle(t)
	dir := t.TempDir()
	anchorPath := writeCLIJSON(t, dir, "anchor.json", c.Chain.Anchor)
	seedPath := writeCLIJSON(t, dir, "seed.json", seed)
	statePath := filepath.Join(dir, "trusted-state.json")
	candidatePath := filepath.Join(dir, "candidate.json")
	common := []string{"--json", "--genesis-config", anchorPath, "--state", statePath}
	query := append(slices.Clone(common), "--retained-only")
	r := checkProcessReport(t, runQueryCLI(t, bins["zenon-spv"], append([]string{"verify-headers"}, append(slices.Clone(common), seedPath)...)...), 0, "ACCEPT")
	if r.Persistence != "saved" || r.Tip.Height != 4009 {
		t.Fatal("seed did not persist the independently pinned tip")
	}
	stateUnchanged := protectCLIState(t, statePath)
	t.Cleanup(stateUnchanged)

	peers := make([]*queryCLIPeer, 3)
	urls := make([]string, len(peers))
	for i := range peers {
		peers[i] = newQueryCLIPeer(t, c, i == 2)
		urls[i] = peers[i].url
	}
	source := []string{"--peers", strings.Join(urls, ","), "--quorum", "2", "--height", "4009", "--count", "8"}
	target := c.Segments[0].RPCAddress + ":1-5"
	collect := append([]string{"--proof-only", "--segments", target}, source...)

	t.Run("collect with an invalid minority", func(t *testing.T) {
		result := runQueryCLI(t, bins["fetch-bundle"], append(slices.Clone(collect), "--out", candidatePath)...)
		if result.code != 0 || len(result.stdout) != 0 || !bytes.Contains(result.stderr, []byte("Verification required:")) || bytes.Contains(result.stderr, []byte("ACCEPT")) {
			t.Fatalf("collector confused collection with verification: %+v", result)
		}
		candidate, err := proof.LoadHeaderBundle(candidatePath)
		if err != nil || len(candidate.Headers) != 0 || len(candidate.Commitments) != 5 || len(candidate.Segments) != 1 || len(candidate.Segments[0].Blocks) != 5 {
			t.Fatalf("collector lost node evidence: %v", err)
		}
		for _, p := range peers {
			if p.calls.Load() == 0 {
				t.Fatal("configured peer was never queried")
			}
		}
	})
	for _, command := range []string{"verify-segment", "verify-commitment"} {
		t.Run(command, func(t *testing.T) {
			result := runQueryCLI(t, bins["zenon-spv"], append([]string{command}, append(slices.Clone(query), "--show-context", candidatePath)...)...)
			assertProcessInclusions(t, checkProcessReport(t, result, 0, "ACCEPT"), seed)
			stateUnchanged()
		})
	}
	t.Run("collector stdout is one complete bundle", func(t *testing.T) {
		result := runQueryCLI(t, bins["fetch-bundle"], append(slices.Clone(collect), "--out", "-")...)
		candidate := readCLIFile(t, candidatePath)
		if result.code != 0 || !json.Valid(result.stdout) || !bytes.Equal(bytes.TrimSpace(candidate), bytes.TrimSpace(result.stdout)) {
			t.Fatal("streamed bundle differs from file output or contains progress logs")
		}
	})
	t.Run("invalid collection arguments make no requests or writes", func(t *testing.T) {
		before := readCLIFile(t, candidatePath)
		var calls int64
		for _, p := range peers {
			calls += p.calls.Load()
		}
		checkpoint := filepath.Join(dir, "forbidden-checkpoint.json")
		for _, args := range [][]string{
			append(slices.Clone(collect), "--checkpoint", checkpoint, "--out", candidatePath),
			append([]string{"--proof-only", "--out", candidatePath}, source...),
		} {
			if result := runQueryCLI(t, bins["fetch-bundle"], args...); result.code != 1 || len(result.stdout) != 0 {
				t.Fatal("invalid collector arguments did not fail before output")
			}
		}
		for _, p := range peers {
			calls -= p.calls.Load()
		}
		if calls != 0 || !bytes.Equal(before, readCLIFile(t, candidatePath)) {
			t.Fatal("invalid collector arguments queried peers or replaced evidence")
		}
		if _, err := os.Stat(checkpoint); !os.IsNotExist(err) {
			t.Fatalf("invalid invocation created a checkpoint: %v", err)
		}
	})
	for _, tc := range []struct {
		name, reason string
		args         []string
	}{
		{"empty headers require explicit mode", "ReasonMissingEvidence", common},
		{"stronger depth refuses", "ReasonInsufficientFinality", append(slices.Clone(query), "--window", "medium")},
		{"missing state cannot bootstrap a query", "ReasonMissingEvidence", selectQueryCLIOption(query, "--state", filepath.Join(dir, "absent.json"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runQueryCLI(t, bins["zenon-spv"], append([]string{"verify-segment"}, append(slices.Clone(tc.args), candidatePath)...)...)
			report := checkProcessReport(t, result, 2, "REFUSED")
			if len(report.Results) == 0 || report.Results[0].Reason != tc.reason {
				t.Fatal("missing evidence or depth lost its refusal reason")
			}
			stateUnchanged()
		})
	}
	for _, tc := range []struct {
		name, reason string
		mutate       func(*proof.HeaderBundle)
	}{
		{"wrong chain", "ReasonChainIDMismatch", func(b *proof.HeaderBundle) { b.ChainID++ }},
		{"tampered flat content", "ReasonInvalidContent", func(b *proof.HeaderBundle) {
			for i := range b.Commitments {
				members := b.Commitments[i].Flat.SortedHeaders
				members[len(members)-1].Hash[0] ^= 1
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate, err := proof.LoadHeaderBundle(candidatePath)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&candidate)
			path := writeCLIJSON(t, t.TempDir(), "tampered.json", candidate)
			result := runQueryCLI(t, bins["zenon-spv"], append([]string{"verify-segment"}, append(slices.Clone(query), path)...)...)
			report := checkProcessReport(t, result, 1, "REJECT")
			if len(report.Results) == 0 || report.Results[0].Reason != tc.reason || len(report.Results[0].Proven) != 0 {
				t.Fatal("invalid evidence acquired an inclusion claim")
			}
			stateUnchanged()
		})
	}
	t.Run("state value remains unsupported", func(t *testing.T) {
		candidate, err := proof.LoadHeaderBundle(candidatePath)
		if err != nil {
			t.Fatal(err)
		}
		candidate.StateValueProofs = []proof.StateValueProof{{ChainID: c.Chain.Anchor.ChainID,
			MomentumHeight: 4003, CommitmentKind: proof.StateCommitmentIAVLState, ProofNodes: [][]byte{{1}}}}
		path := writeCLIJSON(t, t.TempDir(), "state-value.json", candidate)
		result := runQueryCLI(t, bins["zenon-spv"], append([]string{"verify-state-value"}, append(slices.Clone(query), path)...)...)
		report := checkProcessReport(t, result, 2, "REFUSED")
		if len(report.Results) != 1 || report.Results[0].Reason != "ReasonUnsupportedStateCommitment" ||
			len(report.Results[0].Proven) != 0 || !slices.Contains(report.Results[0].NotProven, verify.GuaranteeStateValueInclusion) {
			t.Fatal("state-value report acquired an inclusion guarantee")
		}
		stateUnchanged()
	})
	for _, tc := range []struct {
		name   string
		mode   int32
		detail string
	}{
		{"replaced momentum lists", 1, "invalid JSON-RPC response"}, {"oversized momentum lists", 2, "response does not match query"},
		{"replaced account lists", 3, "invalid JSON-RPC response"}, {"oversized account lists", 4, "response does not match query"},
		{"oversized content", 5, "response exceeds decoded entry limit"},
		{"oversized descendants", 6, "response exceeds decoded entry limit"},
		{"private content conversion errors", 7, "rpc convert momentum failed"},
		{"private token conversion errors", 8, "rpc convert account block failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidateUnchanged := protectCLIState(t, candidatePath)
			t.Cleanup(candidateUnchanged)
			for _, p := range peers {
				p.rangeFault.Store(tc.mode)
			}
			t.Cleanup(func() {
				for _, p := range peers {
					p.rangeFault.Store(0)
				}
			})
			for _, output := range []string{candidatePath, "-"} {
				result := runQueryCLI(t, bins["fetch-bundle"], append(slices.Clone(collect), "--out", output)...)
				if result.code != 1 || len(result.stdout) != 0 || bytes.Contains(bytes.ToUpper(result.stderr), []byte("PRIVATE")) || !bytes.Contains(result.stderr, []byte(tc.detail)) {
					t.Fatal("invalid range lists emitted evidence or accepted collection")
				}
				candidateUnchanged()
			}
			stateUnchanged()
		})
	}
	t.Run("all invalid peers preserve the previous candidate", func(t *testing.T) {
		before := readCLIFile(t, candidatePath)
		for _, p := range peers {
			p.bad.Store(true)
		}
		for _, output := range []string{candidatePath, "-"} {
			result := runQueryCLI(t, bins["fetch-bundle"], append(slices.Clone(collect), "--out", output)...)
			if result.code != 1 || len(result.stdout) != 0 || !bytes.Equal(before, readCLIFile(t, candidatePath)) {
				t.Fatal("failed collection emitted a partial bundle or replaced existing evidence")
			}
		}
		result := runQueryCLI(t, bins["zenon-spv"], append([]string{"verify-segment"}, append(slices.Clone(query), candidatePath)...)...)
		assertProcessInclusions(t, checkProcessReport(t, result, 0, "ACCEPT"), seed)
		stateUnchanged()
	})
	t.Run("accepted headers with failed save exit nonzero", func(t *testing.T) {
		args := append(selectQueryCLIOption(common, "--state", unwritableCLIStatePath(t)), seedPath)
		result := runQueryCLI(t, bins["zenon-spv"], append([]string{"verify-headers"}, args...)...)
		report := checkProcessReport(t, result, 70, "ACCEPT")
		if report.Persistence != "failed" || report.Error == nil || report.Error.Stage != "persistence" {
			t.Fatal("failed persistence was confused with command success")
		}
	})
	t.Run("usage and setup errors have no verification outcome", func(t *testing.T) {
		for _, tc := range []struct {
			code  int
			stage string
			args  []string
		}{
			{64, "arguments", append(slices.Clone(query), "--window", "PRIVATE_WINDOW", candidatePath)},
			{70, "genesis", append(selectQueryCLIOption(query, "--genesis-config", filepath.Join(dir, "PRIVATE_ANCHOR")), candidatePath)},
		} {
			result := runQueryCLI(t, bins["zenon-spv"], append([]string{"verify-segment"}, tc.args...)...)
			report := checkProcessReport(t, result, tc.code, "")
			if report.Error == nil || report.Error.Stage != tc.stage || len(report.Results) != 0 || bytes.Contains(result.stdout, []byte("PRIVATE_")) {
				t.Fatal("setup error disclosed private inputs or reported verification")
			}
		}
		stateUnchanged()
	})
	t.Run("closed stdout does not roll back an already saved state", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = writer.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		path := filepath.Join(dir, "saved-before-output.json")
		args := append([]string{"verify-headers"}, append(selectQueryCLIOption(common, "--state", path), seedPath)...)
		cmd := exec.CommandContext(ctx, bins["zenon-spv"], args...)
		cmd.Env, cmd.Stdout = queryCLIEnvironment(), writer
		cmd.WaitDelay = time.Second
		err = cmd.Run()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || ctx.Err() != nil {
			t.Fatalf("closed stdout did not cause a bounded process failure: %v", err)
		}
		state, err := verify.LoadTrustedState(path, c.Chain.Anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()})
		tip, ok := state.Tip()
		if err != nil || !ok || tip.HeaderHash != seed.Headers[len(seed.Headers)-1].HeaderHash {
			t.Fatalf("stdout failure changed persisted state: %v", err)
		}
	})
}

type queryCLIResult struct {
	code           int
	command        string
	stdout, stderr []byte
	elapsed        time.Duration
	process        *os.ProcessState
	memory         processMemorySample
}

func queryCLIEnvironment() []string {
	var env []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ZENON_SPV_") {
			env = append(env, entry)
		}
	}
	return env
}

// Fixtures that deliberately change an input or policy must select it once;
// appending another flag would exercise usage refusal instead of the intended
// missing-input, context-drift or persistence boundary.
func selectQueryCLIOption(args []string, name, value string) []string {
	selected := slices.Clone(args)
	if i := slices.Index(selected, name); i >= 0 {
		selected[i+1] = value
		return selected
	}
	return append(selected, name, value)
}

func buildQueryCLIs(t *testing.T, names ...string) map[string]string {
	t.Helper()
	// Register CLI sources and their internal helpers as test inputs. Some
	// helpers are only imported by the commands, not by this test package.
	// Their edits must invalidate a previously cached compiled-workflow pass.
	for _, dir := range []string{"../../cmd/zenon-spv", "../../cmd/fetch-bundle", "../../tools/derive-producer-schedule", "../../tools/derive-checkpoints", "../../tools/verify-mainnet-genesis", "../../tools/consume-query-report", "../../tools/observe-block", "../../internal"} {
		if err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				_, err := os.ReadFile(path)
				return err
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"../../go.mod", "../../go.sum"} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("compiled CLI conformance requires the Go toolchain on PATH")
	}
	binDir := t.TempDir()
	bins := make(map[string]string)
	if len(names) == 0 {
		names = []string{"zenon-spv", "fetch-bundle"}
	}
	for _, name := range names {
		pkg := "./cmd/" + name
		switch name {
		case "derive-producer-schedule", "derive-checkpoints", "verify-mainnet-genesis", "consume-query-report", "observe-block":
			pkg = "./tools/" + name
		}
		path := filepath.Join(binDir, name)
		if runtime.GOOS == "windows" {
			path += ".exe"
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		cmd := exec.CommandContext(ctx, goTool, "build", "-trimpath", "-o", path, pkg)
		cmd.Dir = "../.."
		cmd.Env = append(queryCLIEnvironment(), "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=", "GOENV=off")
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("build %s: %v\n%s", name, err, output)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal("cannot open compiled CLI for its execution record")
		}
		digest := sha256.New()
		_, hashErr := io.Copy(digest, file)
		closeErr := file.Close()
		if hashErr != nil || closeErr != nil {
			t.Fatal("cannot hash compiled CLI for its execution record")
		}
		digestHex := fmt.Sprintf("%x", digest.Sum(nil))
		if dir := os.Getenv(candidateExportEnvironment); dir != "" {
			if err := exportCandidateBinary(dir, name, path, digestHex); err != nil {
				t.Fatal("cannot export compiled CLI for the offline candidate")
			}
		}
		record, err := json.Marshal(struct {
			Command string `json:"command"`
			SHA256  string `json:"sha256"`
		}{name, digestHex})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("offline-pilot-binary %s", record)
		bins[name] = path
	}
	return bins
}

func runQueryCLI(t *testing.T, binary string, args ...string) queryCLIResult {
	t.Helper()
	return runQueryCLIWithTimeout(t, 15*time.Second, binary, args...)
}

func runQueryCLIWithTimeout(t *testing.T, timeout time.Duration, binary string, args ...string) queryCLIResult {
	t.Helper()
	return runQueryCLIObserved(t, timeout, false, binary, args...)
}

func runQueryCLIWithResources(t *testing.T, timeout time.Duration, binary string, args ...string) queryCLIResult {
	t.Helper()
	return runQueryCLIObserved(t, timeout, true, binary, args...)
}

func runQueryCLIObserved(t *testing.T, timeout time.Duration, resources bool, binary string, args ...string) queryCLIResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env, cmd.WaitDelay = queryCLIEnvironment(), time.Second
	var out, diagnostics bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &diagnostics
	var err error
	var elapsed time.Duration
	memory := unavailableProcessMemory()
	if resources {
		memory, elapsed, err = runProcessWithMemory(cmd)
	} else {
		start := time.Now()
		err = cmd.Run()
		elapsed = time.Since(start)
	}
	if ctx.Err() != nil {
		t.Fatalf("CLI timed out: %v", ctx.Err())
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	for _, stream := range [][]byte{out.Bytes(), diagnostics.Bytes()} {
		if bytes.Contains(stream, []byte("PRIVATE_RPC")) {
			t.Fatal("CLI disclosed private RPC credentials or query data")
		}
	}
	command := ""
	if len(args) > 0 {
		command = args[0]
	}
	return queryCLIResult{code: code, command: command, stdout: out.Bytes(), stderr: diagnostics.Bytes(), elapsed: elapsed, process: cmd.ProcessState, memory: memory}
}

// Decode independently of the command package so field names, string outcome
// tokens, index zero, and single-value framing are exercised as a consumer sees them.
type processReport struct {
	Version     int                               `json:"schema_version"`
	Command     string                            `json:"command"`
	Mode        string                            `json:"mode"`
	ExitCode    int                               `json:"exit_code"`
	Outcome     string                            `json:"outcome"`
	Persistence string                            `json:"persistence"`
	Error       *struct{ Stage, Category string } `json:"error"`
	Tip         chain.HashHeight                  `json:"verification_tip"`
	Context     *struct {
		Version     int                     `json:"schema_version"`
		Anchor      verify.GenesisTrustRoot `json:"anchor"`
		Fingerprint *chain.Hash             `json:"fingerprint"`
	} `json:"verification_context"`
	Results []struct {
		Reference struct {
			Scope      string               `json:"scope"`
			Index      *int                 `json:"index"`
			BlockIndex *int                 `json:"block_index"`
			Account    *chain.AccountHeader `json:"account_header"`
		} `json:"reference"`
		Outcome   string                   `json:"outcome"`
		Reason    string                   `json:"reason"`
		Proven    []verify.Guarantee       `json:"proven"`
		NotProven []verify.Guarantee       `json:"not_proven"`
		Trust     []verify.TrustAssumption `json:"trust_assumptions"`
	} `json:"results"`
}

func checkProcessReport(t *testing.T, result queryCLIResult, code int, outcome string) processReport {
	t.Helper()
	if result.code != code || len(result.stderr) != 0 {
		t.Fatalf("wrong process outcome: code=%d stdout=%s stderr=%s", result.code, result.stdout, result.stderr)
	}
	var report processReport
	d := json.NewDecoder(bytes.NewReader(result.stdout))
	if err := d.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatalf("mixed or extra stdout content: %v", err)
	}
	if report.Version != 1 || report.ExitCode != code || report.Outcome != outcome || report.Command != result.command {
		t.Fatalf("report does not match process exit: %+v", report)
	}
	if code < 64 && report.Error != nil {
		t.Fatal("verification outcome acquired an operational error")
	}
	return report
}

func assertProcessInclusions(t *testing.T, r processReport, expected proof.HeaderBundle) {
	t.Helper()
	if r.Mode != "retained_only" || r.Persistence != "read_only" || len(r.Results) != 5 || r.Tip.Height != 4009 {
		t.Fatal("query lost its read-only mode, target count, or retained tip")
	}
	if r.Context == nil || r.Context.Version != 1 || r.Context.Fingerprint == nil || r.Context.Anchor.ChainID != expected.ChainID || r.Context.Anchor.HeaderHash != expected.ClaimedGenesis {
		t.Fatal("report lost the configured trust root or context identity")
	}
	for i, row := range r.Results {
		if row.Outcome != "ACCEPT" || !slices.Equal(row.Proven, []verify.Guarantee{verify.GuaranteeContentInclusion}) ||
			row.Reference.Account == nil || *row.Reference.Account != expected.Commitments[i].Target || row.Reference.Index == nil ||
			!slices.Contains(row.Trust, verify.TrustConfiguredAnchor) || !slices.Contains(row.Trust, verify.TrustPersistedState) {
			t.Fatalf("query changed the target or claimed unsupported guarantees: %+v", row)
		}
		if r.Command == "verify-segment" {
			if row.Reference.Scope != "segment" || *row.Reference.Index != 0 || row.Reference.BlockIndex == nil || *row.Reference.BlockIndex != i {
				t.Fatal("wrong segment result reference")
			}
		} else if row.Reference.Scope != "commitment" || *row.Reference.Index != i {
			t.Fatal("wrong commitment result reference")
		}
	}
}

func writeCLIJSON(t *testing.T, dir, name string, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readCLIFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func protectCLIState(t *testing.T, path string) func() {
	t.Helper()
	before := readCLIFile(t, path)
	stamp := time.Unix(1700000000, 0)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		current, err := os.Stat(path)
		if err != nil || !os.SameFile(info, current) || !info.ModTime().Equal(current.ModTime()) || info.Mode() != current.Mode() || !bytes.Equal(before, readCLIFile(t, path)) {
			t.Fatal("query replaced or rewrote trusted state")
		}
	}
}

type queryCLIPeer struct {
	url   string
	bad   atomic.Bool
	calls atomic.Int64
	// 1/2: replaced/excess momentum list; 3/4: account list;
	// 5/6: oversized content/descendants; 7/8: private conversion errors.
	rangeFault atomic.Int32
}

func newQueryCLIPeer(t *testing.T, c accountSegmentCorpus, initiallyBad bool, watchTip ...chain.Header) *queryCLIPeer {
	t.Helper()
	p := &queryCLIPeer{}
	p.bad.Store(initiallyBad)
	var frontier map[string]json.RawMessage
	if len(watchTip) != 0 {
		if err := json.Unmarshal(c.Chain.Vectors[8].Momentum, &frontier); err != nil {
			t.Fatal(err)
		}
		// Only a height hint is synthetic. Every target/range reply below is
		// a byte-for-byte node corpus momentum with its original signature.
		hint := watchTip[0]
		hint.Height++
		hint.PreviousHash = hint.HeaderHash
		hint.TimestampUnix += 10
		hint.HeaderHash = hint.ComputeHash()
		for key, value := range map[string]any{"height": hint.Height, "previousHash": hint.PreviousHash, "timestamp": hint.TimestampUnix, "hash": hint.HeaderHash} {
			frontier[key], _ = json.Marshal(value)
		}
	}
	var goodAccounts []json.RawMessage
	for _, v := range c.Segments[0].Vectors {
		goodAccounts = append(goodAccounts, v.RPC)
	}
	badAccounts := slices.Clone(goodAccounts)
	var receive map[string]json.RawMessage
	if err := json.Unmarshal(badAccounts[2], &receive); err != nil {
		t.Fatal(err)
	}
	var descendants []json.RawMessage
	if err := json.Unmarshal(receive["descendantBlocks"], &descendants); err != nil {
		t.Fatal(err)
	}
	slices.Reverse(descendants)
	var err error
	if receive["descendantBlocks"], err = json.Marshal(descendants); err != nil {
		t.Fatal(err)
	}
	if badAccounts[2], err = json.Marshal(receive); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != "PRIVATE_RPC_USER" || password != "PRIVATE_RPC_PASSWORD" || r.URL.Query().Get("token") != "PRIVATE_RPC_QUERY" {
			t.Error("collector changed configured RPC credentials")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var request struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var list []json.RawMessage
		switch request.Method {
		case "ledger.getFrontierMomentum":
			if frontier == nil {
				t.Error("unexpected frontier query")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": frontier}); err != nil {
				t.Error(err)
			}
			return
		case "ledger.getMomentumsByHeight":
			var start, count uint64
			valid := len(request.Params) == 2 && json.Unmarshal(request.Params[0], &start) == nil && json.Unmarshal(request.Params[1], &count) == nil
			if frontier != nil {
				valid = valid && start >= 4001 && start <= 4009 && count > 0 && count <= 4010-start
			} else {
				valid = valid && (start == 4001 && count == 9 || start == 4009 && count == 1)
			}
			if !valid {
				t.Error("unexpected momentum query")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			for i := uint64(0); i < count; i++ {
				list = append(list, c.Chain.Vectors[start-4001+i].Momentum)
			}
		case "ledger.getAccountBlocksByHeight":
			got, _ := json.Marshal(request.Params)
			want, _ := json.Marshal([]any{c.Segments[0].RPCAddress, 1, 5})
			if !bytes.Equal(got, want) {
				t.Error("unexpected account query")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			list = goodAccounts
			if p.bad.Load() {
				list = badAccounts
			}
		default:
			t.Error("unexpected RPC method")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mode := p.rangeFault.Load()
		if (mode == 7 && request.Method == "ledger.getMomentumsByHeight") ||
			(mode == 8 && request.Method == "ledger.getAccountBlocksByHeight") {
			list = slices.Clone(list)
			field := "content"
			if mode == 8 {
				field = "tokenStandard"
			}
			list[0] = privateRPCConversionValue(t, list[0], field)
		}
		if (mode == 5 && request.Method == "ledger.getMomentumsByHeight") ||
			(mode == 6 && request.Method == "ledger.getAccountBlocksByHeight") {
			list = slices.Clone(list)
			field := "content"
			if mode == 6 {
				field = "descendantBlocks"
			}
			list[0] = oversizedRPCMembers(field)
		}
		if ((mode == 1 || mode == 2) && request.Method == "ledger.getMomentumsByHeight") ||
			((mode == 3 || mode == 4) && request.Method == "ledger.getAccountBlocksByHeight") {
			raw, err := json.Marshal(list)
			if err != nil {
				t.Error(err)
				return
			}
			if mode == 1 || mode == 3 {
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"list":[null],"LI\u017fT":%s}}`, request.ID, raw)
			} else {
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"list":%s,"PRIVATE_UNREACHED_ROW"]}}`, request.ID, raw[:len(raw)-1])
			}
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": map[string]any{"list": list}}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	p.url = strings.Replace(server.URL, "http://", "http://PRIVATE_RPC_USER:PRIVATE_RPC_PASSWORD@", 1) + "?token=PRIVATE_RPC_QUERY"
	return p
}

func unwritableCLIStatePath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if probe, err := os.CreateTemp(dir, "permission-probe-"); err == nil {
		_ = probe.Close()
		t.Skip("filesystem or process privileges allow writes in a read-only directory")
	}
	return path
}
