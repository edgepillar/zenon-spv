package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func accountSegmentPeer(t *testing.T, failAt int64) (string, segmentSpec, proof.AccountSegment, *atomic.Int64) {
	t.Helper()
	raw, err := os.ReadFile("../../internal/testdata/conformance/account-amounts.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			RPC   json.RawMessage    `json:"rpc"`
			Block chain.AccountBlock `json:"block"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	v := corpus.Vectors[1] // the pinned node's ordinary synthetic amount
	var fields struct{ Address string }
	if err := json.Unmarshal(v.RPC, &fields); err != nil {
		t.Fatal(err)
	}
	spec := segmentSpec{addressBech32: fields.Address, address: v.Block.Address, startHeight: v.Block.Height, count: 1}
	segment := proof.AccountSegment{Address: v.Block.Address, Blocks: []chain.AccountBlock{v.Block}}
	headers, _ := bundleFixturePeer(t)
	requests := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		var result any
		if req.Method == "ledger.getAccountBlocksByHeight" {
			if requests.Add(1) == failAt {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			want, _ := json.Marshal([]any{spec.addressBech32, spec.startHeight, spec.count})
			got, _ := json.Marshal(req.Params)
			if !bytes.Equal(got, want) {
				t.Errorf("unexpected account query: %s", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			result = map[string]any{"list": []json.RawMessage{v.RPC}}
		} else {
			// Forward only to another local fixture for the CLI's header phase.
			var wire json.RawMessage
			if err := fetch.NewClient(headers).Call(r.Context(), req.Method, req.Params, &wire); err != nil {
				t.Error(err)
				return
			}
			result = wire
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL, spec, segment, requests
}

func TestSegmentEncodingStopsRPCOnOverflowOrSourceFailure(t *testing.T) {
	for _, multi := range []bool{false, true} {
		for _, mode := range []string{"exact fit", "overflow", "source failure"} {
			t.Run(fmt.Sprintf("multi=%t/%s", multi, mode), func(t *testing.T) {
				var failAt int64
				if mode == "source failure" {
					failAt = 2
				}
				a, spec, segment, aCalls := accountSegmentPeer(t, failAt)
				b, _, _, bCalls := accountSegmentPeer(t, failAt)
				bundle := proof.HeaderBundle{Version: proof.WireVersion, Segments: []proof.AccountSegment{segment, segment}}
				want, err := json.Marshal(bundle)
				if err != nil {
					t.Fatal(err)
				}
				want = append(want, '\n')
				limit, count := int64(len(want)), 2
				switch mode {
				case "overflow":
					one := bundle
					one.Segments = one.Segments[:1]
					encoded, err := json.Marshal(one)
					if err != nil {
						t.Fatal(err)
					}
					limit, count = int64(len(encoded)+1), 10
				case "source failure":
					limit, count = 1<<20, 10
				}
				bundle.Segments = nil // production obtains segments only from RPC
				got, err := encodeBundleWithSegments(bundle, limit, count, func(int) (proof.AccountSegment, error) {
					return fetchSegment(context.Background(), []string{a, b}, multi, a, 2, spec)
				})
				if mode == "exact fit" {
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("streamed RPC output differs from standard JSON: %v", err)
					}
				} else if err == nil || got != nil {
					t.Fatalf("failed source or overflow returned partial bytes: len=%d err=%v", len(got), err)
				} else if mode == "overflow" && !errors.Is(err, proof.ErrBundleTooLarge) {
					t.Fatalf("wrong overflow error: %v", err)
				}
				if aCalls.Load() != 2 || (multi && bCalls.Load() != 2) || (!multi && bCalls.Load() != 0) {
					t.Fatalf("continued RPC after failure or selected wrong peers: a=%d b=%d", aCalls.Load(), bCalls.Load())
				}
			})
		}
	}
}

func TestSegmentEncodingCancellationDiscardsPrefix(t *testing.T) {
	peer, spec, _, calls := accountSegmentPeer(t, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got, err := encodeBundleWithSegments(proof.HeaderBundle{Version: proof.WireVersion}, 1<<20, 10, func(i int) (proof.AccountSegment, error) {
		segment, err := fetchSegment(ctx, nil, false, peer, 0, spec)
		if i == 0 {
			cancel()
		}
		return segment, err
	})
	if !errors.Is(err, context.Canceled) || got != nil || calls.Load() != 1 {
		t.Fatalf("canceled encoding returned bytes or continued RPC: len=%d calls=%d err=%v", len(got), calls.Load(), err)
	}
}

func TestBundleSegmentFetchPublishesOnlyCompleteOutput(t *testing.T) {
	t.Setenv("ZENON_SPV_RPC", "")
	t.Setenv("ZENON_SPV_PEERS", "")
	for _, failAt := range []int64{0, 2} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("fail=%d/existing=%t", failAt, existing), func(t *testing.T) {
				peer, spec, segment, calls := accountSegmentPeer(t, failAt)
				dir := t.TempDir()
				paths := []string{filepath.Join(dir, "bundle.json"), filepath.Join(dir, "anchor.json")}
				before := []byte("previous output")
				if existing {
					for _, path := range paths {
						if err := os.WriteFile(path, before, 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}
				query := fmt.Sprintf("%s:%d", spec.addressBech32, spec.startHeight)
				err := run([]string{"--rpc", peer, "--height", "1006", "--count", "5", "--segments", query + "," + query, "--out", paths[0], "--checkpoint", paths[1]})
				if calls.Load() != 2 {
					t.Fatalf("wrong account request count: %d", calls.Load())
				}
				if failAt == 0 {
					if err != nil {
						t.Fatal(err)
					}
					checkFixtureBundle(t, paths[0], paths[1])
					raw, err := os.ReadFile(paths[0])
					if err != nil {
						t.Fatal(err)
					}
					var bundle proof.HeaderBundle
					if err := json.Unmarshal(raw, &bundle); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(bundle.Segments, []proof.AccountSegment{segment, segment}) {
						t.Fatal("streaming changed or dropped account evidence")
					}
				} else {
					if err == nil || !strings.Contains(err.Error(), "fetch segment 2") {
						t.Fatalf("late RPC error missing: %v", err)
					}
					for _, path := range paths {
						raw, err := os.ReadFile(path)
						if existing && (err != nil || !bytes.Equal(raw, before)) || !existing && !os.IsNotExist(err) {
							t.Fatal("late RPC failure published output")
						}
					}
				}
			})
		}
	}
}
