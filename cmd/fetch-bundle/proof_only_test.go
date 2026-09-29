package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type proofQueryCorpus struct {
	Source struct{ Commit string }
	Chain  struct {
		Anchor  verify.GenesisTrustRoot
		Vectors []struct {
			Header   chain.Header
			Momentum json.RawMessage
			Content  []chain.AccountHeader
		}
	}
	Segments []struct {
		Address    chain.Address
		RPCAddress string `json:"rpc_address"`
		Vectors    []struct {
			Block chain.AccountBlock
			RPC   json.RawMessage
		}
	}
}

func loadProofQueryCorpus(t *testing.T) proofQueryCorpus {
	t.Helper()
	raw, err := os.ReadFile("../../internal/testdata/conformance/contract-batches.json")
	if err != nil {
		t.Fatal(err)
	}
	var c proofQueryCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Source.Commit != "3a4131e63881058b6ce2ee81d3a41d0033fafc99" || len(c.Chain.Vectors) != 9 || len(c.Segments) != 1 || len(c.Segments[0].Vectors) != 5 {
		t.Fatal("unexpected pinned node corpus")
	}
	return c
}

func (c proofQueryCorpus) retainedState(t *testing.T) verify.VerifiedState {
	t.Helper()
	opts := verify.VerifyOptions{Policy: verify.DefaultPolicy()}
	state, err := verify.NewVerifiedState(c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	var headers []chain.Header
	for _, v := range c.Chain.Vectors {
		headers = append(headers, v.Header)
	}
	result, state := state.Extend(headers)
	if result.Outcome != verify.OutcomeAccept {
		t.Fatal(result)
	}
	path := filepath.Join(t.TempDir(), "trusted-state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := verify.LoadTrustedState(path, c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func (c proofQueryCorpus) peer(t *testing.T, differentContent bool) (string, *atomic.Int64) {
	t.Helper()
	momentums := make(map[uint64]json.RawMessage)
	for _, v := range c.Chain.Vectors {
		raw := v.Momentum
		if differentContent && len(v.Content) != 0 {
			// A self-consistent RPC hash is still not the retained header's
			// content commitment. The collector must not call this verified.
			content := slices.Clone(v.Content)
			content[len(content)-1].Hash[0] ^= 1
			header := v.Header
			header.ContentHash = chain.MomentumContentHash(content)
			var wire map[string]any
			if err := json.Unmarshal(raw, &wire); err != nil {
				t.Fatal(err)
			}
			wire["content"].([]any)[len(content)-1].(map[string]any)["hash"] = content[len(content)-1].Hash
			wire["hash"] = header.ComputeHash()
			var err error
			raw, err = json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
		}
		momentums[v.Header.Height] = raw
	}
	calls := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req struct {
			ID     json.RawMessage
			Method string
			Params []json.RawMessage
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var result any
		switch req.Method {
		case "ledger.getFrontierMomentum":
			result = momentums[4009]
		case "ledger.getMomentumsByHeight":
			var start, count uint64
			if len(req.Params) != 2 || json.Unmarshal(req.Params[0], &start) != nil || json.Unmarshal(req.Params[1], &count) != nil ||
				(start != 4001 || count != 9) && (start != 4009 || count != 1) {
				t.Error("unexpected momentum query")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			list := make([]json.RawMessage, count)
			for i := range list {
				list[i] = momentums[start+uint64(i)]
			}
			result = map[string]any{"list": list}
		case "ledger.getAccountBlocksByHeight":
			want, _ := json.Marshal([]any{c.Segments[0].RPCAddress, 1, 5})
			got, _ := json.Marshal(req.Params)
			if !bytes.Equal(got, want) {
				t.Error("unexpected account query")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var list []json.RawMessage
			for _, v := range c.Segments[0].Vectors {
				list = append(list, v.RPC)
			}
			result = map[string]any{"list": list}
		default:
			t.Error("unexpected RPC method")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL, calls
}

func TestProofOnlyBundleFeedsRetainedQueries(t *testing.T) {
	t.Setenv("ZENON_SPV_RPC", "")
	t.Setenv("ZENON_SPV_PEERS", "")
	c := loadProofQueryCorpus(t)
	state := c.retainedState(t)
	for _, mode := range []string{"commitments", "segments", "multi pinned", "multi frontier", "default headers", "explicit false"} {
		t.Run(mode, func(t *testing.T) {
			a, aCalls := c.peer(t, false)
			b, bCalls := c.peer(t, false)
			path := filepath.Join(t.TempDir(), "bundle.json")
			args := []string{"--rpc", a, "--height", "4009", "--count", "8", "--out", path}
			proofOnly := mode != "default headers" && mode != "explicit false"
			if proofOnly {
				args = append(args, "--proof-only")
			} else {
				args = append(args, "--checkpoint", filepath.Join(t.TempDir(), "observed-checkpoint.json"))
			}
			if mode == "explicit false" {
				args = append(args, "--proof-only=false")
			}
			if mode == "commitments" {
				args = append(args, "--commitments", c.Segments[0].RPCAddress)
			} else {
				args = append(args, "--segments", c.Segments[0].RPCAddress+":1-5")
			}
			multi := strings.HasPrefix(mode, "multi")
			if multi {
				args = append(args, "--peers", a+","+b, "--quorum", "2")
			}
			if mode == "multi frontier" {
				args = append(args, "--height", "-1", "--safety-margin", "0")
			}
			if err := run(args); err != nil {
				t.Fatal(err)
			}
			bundle, err := proof.LoadHeaderBundle(path)
			if err != nil {
				t.Fatal(err)
			}
			wantHeaders := 8
			if proofOnly {
				wantHeaders = 0
			}
			if len(bundle.Headers) != wantHeaders || len(bundle.Commitments) != 5 || bundle.ChainID != c.Chain.Anchor.ChainID || bundle.ClaimedGenesis != c.Chain.Vectors[0].Header.HeaderHash {
				t.Fatal("wrong candidate envelope or dropped evidence")
			}
			if aCalls.Load() == 0 || multi && bCalls.Load() == 0 || !multi && bCalls.Load() != 0 {
				t.Fatal("wrong peer selection")
			}
			check := func(r verify.Result) {
				t.Helper()
				if r.Outcome != verify.OutcomeAccept || !reflect.DeepEqual(r.Proven, []verify.Guarantee{verify.GuaranteeContentInclusion}) || !slices.Contains(r.TrustAssumptions, verify.TrustPersistedState) {
					t.Fatalf("unexpected retained query result: %+v", r)
				}
			}
			for _, e := range bundle.Commitments {
				check(state.VerifyCommitment(e))
			}
			if mode == "commitments" {
				if len(bundle.Segments) != 0 {
					t.Fatal("commitment-only request fetched segments")
				}
				return
			}
			if len(bundle.Segments) != 1 || len(bundle.Segments[0].Blocks) != 5 {
				t.Fatal("missing contract segment")
			}
			for _, r := range state.VerifySegment(bundle.Segments[0], bundle.Commitments).Blocks {
				check(r)
			}
		})
	}
}

func TestProofOnlyInvalidOptionsDoNotFetchOrPublish(t *testing.T) {
	peer, calls := bundleFixturePeer(t)
	t.Setenv("ZENON_SPV_RPC", "")
	t.Setenv("ZENON_SPV_PEERS", "")
	for _, mode := range []string{"no targets", "empty targets", "checkpoint file", "checkpoint stdout"} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%t", mode, existing), func(t *testing.T) {
				dir := t.TempDir()
				paths := []string{filepath.Join(dir, "bundle.json"), filepath.Join(dir, "anchor.json")}
				before := []byte("previous output")
				for _, path := range paths {
					if existing {
						if err := os.WriteFile(path, before, 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}
				args := []string{"--proof-only", "--rpc", peer, "--out", paths[0]}
				switch mode {
				case "empty targets":
					args = append(args, "--commitments", " , , ", "--segments", " , ")
				case "checkpoint file", "checkpoint stdout":
					destination := paths[1]
					if mode == "checkpoint stdout" {
						destination = "-"
					}
					args = append(args, "--commitments", "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f", "--checkpoint", destination)
				}
				if err := run(args); err == nil || !strings.Contains(err.Error(), "--proof-only") {
					t.Fatalf("invalid mode was not refused: %v", err)
				}
				if calls.Load() != 0 {
					t.Fatal("invalid options reached RPC")
				}
				for _, path := range paths {
					raw, err := os.ReadFile(path)
					if existing && (err != nil || !bytes.Equal(raw, before)) || !existing && !os.IsNotExist(err) {
						t.Fatal("invalid options changed output")
					}
				}
			})
		}
	}
}

func TestProofOnlySourceDoesNotOverrideRetainedCommitment(t *testing.T) {
	c := loadProofQueryCorpus(t)
	state := c.retainedState(t)
	peer, _ := c.peer(t, true)
	path := filepath.Join(t.TempDir(), "candidate.json")
	if err := run([]string{"--proof-only", "--rpc", peer, "--height", "4009", "--count", "8", "--segments", c.Segments[0].RPCAddress + ":1-5", "--out", path}); err != nil {
		t.Fatal(err)
	}
	bundle, err := proof.LoadHeaderBundle(path)
	if err != nil || len(bundle.Commitments) != 5 || len(bundle.Segments) != 1 || len(bundle.Headers) != 0 {
		t.Fatalf("unexpected candidate: %v", err)
	}
	for _, evidence := range bundle.Commitments {
		r := state.VerifyCommitment(evidence)
		if r.Outcome != verify.OutcomeReject || r.Reason != verify.ReasonInvalidContent || len(r.Proven) != 0 {
			t.Fatal("peer content displaced the retained commitment", r)
		}
	}
	r := state.VerifySegment(bundle.Segments[0], bundle.Commitments)
	if r.Worst() != verify.OutcomeReject {
		t.Fatal("account query accepted the peer's altered content")
	}
	for _, block := range r.Blocks {
		if block.Outcome == verify.OutcomeAccept || len(block.Proven) != 0 {
			t.Fatal("altered candidate gained a block guarantee")
		}
	}
}

func TestProofOnlyLateFailuresPreserveOutput(t *testing.T) {
	t.Setenv("ZENON_SPV_RPC", "")
	t.Setenv("ZENON_SPV_PEERS", "")
	for _, mode := range []string{"late account RPC", "aggregate evidence", "encoded byte cap"} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%t", mode, existing), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "bundle.json")
				before := []byte("existing candidate")
				if existing {
					if err := os.WriteFile(path, before, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				args := []string{"--proof-only", "--out", path}
				want := "fetch segment 2"
				if mode == "late account RPC" {
					peer, spec, _, calls := accountSegmentPeer(t, 2)
					query := fmt.Sprintf("%s:%d", spec.addressBech32, spec.startHeight)
					args = append(args, "--rpc", peer, "--height", "1006", "--count", "5", "--segments", query+","+query)
					t.Cleanup(func() {
						if calls.Load() != 2 {
							t.Error("continued after source failure")
						}
					})
				} else {
					members := 1001
					want = "aggregate flat evidence"
					if mode == "encoded byte cap" {
						members, want = 1000, "bundle exceeds size cap"
					}
					peer := expansionPeer(t, members)
					args = append(args, "--rpc", peer, "--height", "1002", "--count", "1", "--segments", "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f:1")
				}
				if err := run(args); err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("expected bounded failure, got %v", err)
				}
				raw, err := os.ReadFile(path)
				if existing && (err != nil || !bytes.Equal(raw, before)) || !existing && !os.IsNotExist(err) {
					t.Fatal("failed candidate replaced or created output")
				}
			})
		}
	}
}
