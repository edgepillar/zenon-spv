package main

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Serve the pinned node's synthetic v1 chain through the actual RPC path.
func bundleFixturePeer(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	raw, err := os.ReadFile("../../internal/testdata/conformance/momentum-v1-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Chain struct {
			Vectors []struct {
				Header struct {
					Height uint64 `json:"height"`
				} `json:"header"`
				Momentum json.RawMessage `json:"momentum"`
			} `json:"vectors"`
		} `json:"chain"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	wire := make(map[uint64]json.RawMessage)
	for _, v := range corpus.Chain.Vectors {
		wire[v.Header.Height] = v.Momentum
	}
	if len(wire) != 6 || wire[1006] == nil {
		t.Fatal("unexpected fixture chain")
	}
	requests := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params []uint64        `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var result any
		switch req.Method {
		case "ledger.getFrontierMomentum":
			result = wire[1006]
		case "ledger.getMomentumsByHeight":
			if len(req.Params) != 2 || req.Params[1] > 6 {
				t.Error("unexpected range")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			list := make([]json.RawMessage, req.Params[1])
			for i := range list {
				list[i] = wire[req.Params[0]+uint64(i)]
				if list[i] == nil {
					t.Error("height outside fixture")
					w.WriteHeader(http.StatusNotFound)
					return
				}
			}
			result = map[string]any{"list": list}
		default:
			t.Error("unexpected method")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL, requests
}

func TestBundleSinglePeerSelectionOverridesRPCFallback(t *testing.T) {
	for _, source := range []string{"flag", "environment"} {
		t.Run(source, func(t *testing.T) {
			selected, requests := bundleFixturePeer(t)
			var fallbackRequests atomic.Int64
			fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fallbackRequests.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer fallback.Close()
			t.Setenv("ZENON_SPV_PEERS", "")
			t.Setenv("ZENON_SPV_RPC", fallback.URL)
			dir := t.TempDir()
			bundlePath, anchorPath := filepath.Join(dir, "bundle.json"), filepath.Join(dir, "anchor.json")
			args := []string{"--peers", selected, "--height", "1006", "--count", "5", "--out", bundlePath, "--checkpoint", anchorPath}
			if source == "flag" {
				args = append(args, "--rpc", fallback.URL)
			}
			if err := run(args); err != nil {
				t.Fatalf("selected peer was not used: %v", err)
			}
			if requests.Load() == 0 || fallbackRequests.Load() != 0 {
				t.Fatal("peer selection contacted the wrong endpoint")
			}
			checkFixtureBundle(t, bundlePath, anchorPath)
		})
	}
}

func checkFixtureBundle(t *testing.T, bundlePath, anchorPath string) {
	t.Helper()
	var bundle proof.HeaderBundle
	var anchor verify.GenesisTrustRoot
	for path, target := range map[string]any{bundlePath: &bundle, anchorPath: &anchor} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			t.Fatal(err)
		}
	}
	if len(bundle.Headers) != 5 || anchor.Height != 1001 || bundle.ClaimedGenesis != anchor.HeaderHash || bundle.Headers[4].Height != 1006 {
		t.Fatal("wrong bundle or anchor")
	}
	policy := verify.DefaultPolicy()
	policy.W = 1 // Match the short, synthetic conformance experiment.
	state, err := verify.NewVerifiedState(anchor, verify.VerifyOptions{Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	result, _ := state.Extend(bundle.Headers)
	if result.Outcome != verify.OutcomeAccept {
		t.Fatalf("emitted fixture bundle failed verification: %s", result)
	}
}

func TestBundleFetchModesProduceVerifiableFiles(t *testing.T) {
	for _, mode := range []string{"rpc fallback", "multi pinned", "multi frontier"} {
		t.Run(mode, func(t *testing.T) {
			a, requestsA := bundleFixturePeer(t)
			b, requestsB := bundleFixturePeer(t)
			t.Setenv("ZENON_SPV_RPC", a)
			t.Setenv("ZENON_SPV_PEERS", "")
			dir := t.TempDir()
			bundlePath, anchorPath := filepath.Join(dir, "bundle.json"), filepath.Join(dir, "anchor.json")
			args := []string{"--count", "5", "--out", bundlePath, "--checkpoint", anchorPath}
			switch mode {
			case "rpc fallback":
				args = append(args, "--height", "1006", "--quorum", "1")
			case "multi pinned":
				args = append(args, "--peers", a+","+b, "--height", "1006", "--quorum", "2")
			case "multi frontier":
				args = append(args, "--peers", a+","+b, "--height", "-1", "--quorum", "0", "--safety-margin", "0")
			}
			if err := run(args); err != nil {
				t.Fatal(err)
			}
			if requestsA.Load() == 0 || (mode != "rpc fallback" && requestsB.Load() == 0) {
				t.Fatal("selected fetch mode was not exercised")
			}
			if mode == "rpc fallback" && requestsB.Load() != 0 {
				t.Fatal("single-peer fetch contacted another endpoint")
			}
			checkFixtureBundle(t, bundlePath, anchorPath)
		})
	}
}

func TestBundleExplicitRPCOverridesPeerEnvironment(t *testing.T) {
	selected, requests := bundleFixturePeer(t)
	var unwantedRequests atomic.Int64
	unwanted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		unwantedRequests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unwanted.Close()
	t.Setenv("ZENON_SPV_PEERS", unwanted.URL)
	t.Setenv("ZENON_SPV_RPC", unwanted.URL)
	dir := t.TempDir()
	bundlePath, anchorPath := filepath.Join(dir, "bundle.json"), filepath.Join(dir, "anchor.json")
	if err := run([]string{"--rpc", selected, "--height", "1006", "--count", "5", "--out", bundlePath, "--checkpoint", anchorPath}); err != nil {
		t.Fatalf("explicit RPC was overridden by environment: %v", err)
	}
	if requests.Load() == 0 || unwantedRequests.Load() != 0 {
		t.Fatal("explicit RPC selection contacted an environment endpoint")
	}
	checkFixtureBundle(t, bundlePath, anchorPath)
	before := requests.Load()
	if err := run([]string{"--rpc", ""}); err == nil {
		t.Fatal("empty explicit RPC selection fell back to an environment peer")
	}
	if requests.Load() != before || unwantedRequests.Load() != 0 {
		t.Fatal("empty explicit RPC selection reached a peer")
	}
}

func TestBundleLowFrontierStopsBeforeRangeAndOutput(t *testing.T) {
	peer, requests := bundleFixturePeer(t)
	t.Setenv("ZENON_SPV_RPC", "")
	t.Setenv("ZENON_SPV_PEERS", "")
	dir := t.TempDir()
	bundlePath, anchorPath := filepath.Join(dir, "bundle.json"), filepath.Join(dir, "anchor.json")
	err := run([]string{"--rpc", peer, "--height", "-1", "--count", "1006", "--out", bundlePath, "--checkpoint", anchorPath})
	if err == nil || !strings.Contains(err.Error(), "positive checkpoint") || requests.Load() != 1 {
		t.Fatalf("low frontier reached a header-range request: requests=%d err=%v", requests.Load(), err)
	}
	for _, path := range []string{bundlePath, anchorPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("low frontier created output")
		}
	}
}

func TestBundleInvalidOptionsStopBeforeRPCOrOutput(t *testing.T) {
	const address = "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f"
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	t.Setenv("ZENON_SPV_RPC", "")
	t.Setenv("ZENON_SPV_PEERS", "")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"zero count", []string{"--count", "0"}, "--count"},
		{"large count", []string{"--count", strconv.Itoa(verify.DefaultMaxHeaders + 1)}, "--count"},
		{"overflowing count", []string{"--count", strconv.Itoa(math.MaxInt)}, "--count"},
		{"negative height", []string{"--height", "-2"}, "--height"},
		{"zero height", []string{"--height", "0"}, "--height"},
		{"zero checkpoint", []string{"--height", "5"}, "--height"},
		{"short range", []string{"--height", "4"}, "--height"},
		{"zero timeout", []string{"--timeout", "0s"}, "--timeout"},
		{"negative timeout", []string{"--timeout", "-1s"}, "--timeout"},
		{"negative quorum", []string{"--quorum", "-1"}, "--quorum"},
		{"excessive quorum", []string{"--quorum", "2"}, "--quorum"},
		{"positional input", []string{"unexpected"}, "positional"},
		{"zero segment height", []string{"--segments", address + ":0"}, "--segments"},
		{"overflowing segment", []string{"--segments", address + ":0-18446744073709551615"}, "--segments"},
		{"large segment", []string{"--segments", address + ":1-10001"}, "--segments"},
		{"too many segments", []string{"--segments", strings.Repeat(address+":1,", verify.DefaultMaxSegments+1)}, "--segments"},
		{"too many total blocks", []string{"--segments", strings.Repeat(address+":1-10000,", 11)}, "--segments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, existing := range []bool{false, true} {
				dir := t.TempDir()
				paths := []string{filepath.Join(dir, "bundle.json"), filepath.Join(dir, "anchor.json")}
				before := []byte("existing output must remain unchanged")
				if existing {
					for _, path := range paths {
						if err := os.WriteFile(path, before, 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}
				args := []string{"--rpc", server.URL, "--peers", "", "--height", "1006", "--count", "5", "--out", paths[0], "--checkpoint", paths[1]}
				args = append(args, tc.args...)
				if err := run(args); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("invalid setup was not refused early: %v", err)
				}
				if requests.Load() != 0 {
					t.Fatal("invalid setup reached RPC")
				}
				for _, path := range paths {
					after, err := os.ReadFile(path)
					if existing {
						if err != nil || !bytes.Equal(before, after) {
							t.Fatal("invalid setup replaced existing output")
						}
					} else if !os.IsNotExist(err) {
						t.Fatal("invalid setup created output")
					}
				}
			}
		})
	}
}

func TestSegmentQueryBoundaries(t *testing.T) {
	const address = "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f"
	for _, tc := range []struct {
		spec     string
		segments int
		total    uint64
	}{
		{address + ":18446744073709551615", 1, 1},
		{address + ":18446744073709551614-18446744073709551615", 1, 2},
		{address + ":1-10000", 1, 10000},
		{strings.Repeat(address+":1-10000,", 10), 10, 100000},
		{strings.Repeat(address+":1,", 1000), 1000, 1000},
	} {
		specs, err := parseSegmentSpecs(tc.spec)
		if err != nil || len(specs) != tc.segments {
			t.Fatalf("valid boundary failed: segments=%d err=%v", len(specs), err)
		}
		var total uint64
		for _, spec := range specs {
			total += spec.count
			if spec.startHeight == 0 || spec.count == 0 {
				t.Fatal("invalid parsed range")
			}
		}
		if total != tc.total {
			t.Fatalf("total blocks=%d, want %d", total, tc.total)
		}
	}
}
