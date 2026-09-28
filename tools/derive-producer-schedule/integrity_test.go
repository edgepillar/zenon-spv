package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func signFixtureHeader(h *chain.Header) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	h.HeaderHash = h.ComputeHash()
	h.Signature = ed25519.Sign(key, h.HeaderHash[:])
}

func TestDeriveScheduleAgreeingInvalidObservations(t *testing.T) {
	cases := []struct {
		name     string
		index    int
		frontier bool
		mutate   func(*chain.Header)
		want     string
	}{
		{"wrong chain", 2, false, func(h *chain.Header) { h.ChainIdentifier++; signFixtureHeader(h) }, "chain ID"},
		{"invalid signature", 2, false, func(h *chain.Header) { h.Signature[0] ^= 1 }, "invalid header signature"},
		{"missing signature", 2, false, func(h *chain.Header) { h.Signature = nil }, "invalid header signature"},
		{"missing key", 2, false, func(h *chain.Header) { h.PublicKey = nil }, "invalid header signature"},
		{"short key", 2, false, func(h *chain.Header) { h.PublicKey = h.PublicKey[:31] }, "invalid header signature"},
		{"broken in batch", 1, false, func(h *chain.Header) { h.PreviousHash[0] ^= 1; signFixtureHeader(h) }, "broken linkage"},
		{"broken across batches", 4, false, func(h *chain.Header) { h.PreviousHash[0] ^= 1; signFixtureHeader(h) }, "broken linkage"},
		{"wrong height", 2, false, func(h *chain.Header) { h.Height++; signFixtureHeader(h) }, "expected height"},
		{"unknown layout", 2, false, func(h *chain.Header) { h.Version = 3; signFixtureHeader(h) }, "unsupported momentum version"},
		{"wrong frontier chain", 5, true, func(h *chain.Header) { h.ChainIdentifier++; signFixtureHeader(h) }, "frontier: height 1006: chain ID"},
		{"invalid frontier signature", 5, true, func(h *chain.Header) { h.Signature[0] ^= 1 }, "frontier: height 1006: invalid header signature"},
		{"conflicting frontier", 5, true, func(h *chain.Header) { h.TimestampUnix++; signFixtureHeader(h) }, "frontier differs"},
		{"substituted frontier signer", 5, true, func(h *chain.Header) {
			seed := make([]byte, ed25519.SeedSize)
			seed[0] = 7
			key := ed25519.NewKeyFromSeed(seed)
			h.PublicKey = key.Public().(ed25519.PublicKey)
			h.Signature = ed25519.Sign(key, h.HeaderHash[:])
		}, "frontier differs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers, preimages := makeChain(t, 6)
			corrupt := headers[tc.index]
			corrupt.Signature = bytes.Clone(corrupt.Signature)
			corrupt.PublicKey = bytes.Clone(corrupt.PublicKey)
			tc.mutate(&corrupt)
			var frontier map[string]any
			var overrides map[uint64]map[string]any
			wire := momentumJSON(corrupt, preimages[tc.index])
			if tc.frontier {
				frontier = wire
			} else {
				overrides = map[uint64]map[string]any{headers[tc.index].Height: wire}
			}
			urls := make([]string, 3)
			for i := range urls {
				srv := startPeerWithFrontier(t, headers, preimages, overrides, frontier)
				t.Cleanup(srv.Close)
				urls[i] = srv.URL
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s, err := deriveSchedule(ctx, fetch.NewMultiClient(urls), 99, 1001, 1006, 4, io.Discard)
			if s != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want no schedule and %q, got schedule=%v err=%v", tc.want, s != nil, err)
			}
		})
	}
}

func TestDeriveSchedulePreflightBeforeRPC(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	cases := []struct {
		name    string
		from    uint64
		through uint64
		mutate  func(*fetch.MultiClient)
		want    string
	}{
		{"zero", 0, 6, nil, "after genesis"},
		{"genesis", 1, 6, nil, "after genesis"},
		{"reversed", 6, 2, nil, "end at or above"},
		{"too many entries", 2, verify.MaxProducerScheduleEntries + 2, nil, "resource limit"},
		{"huge range", 2, math.MaxUint64, nil, "resource limit"},
		{"single peer", 2, 6, func(m *fetch.MultiClient) { m.Peers = m.Peers[:1] }, "two distinct peers"},
		{"duplicate peer", 2, 6, func(m *fetch.MultiClient) { m.Peers[1] = m.Peers[0] }, "duplicate peer"},
		{"nil peer", 2, 6, func(m *fetch.MultiClient) { m.Peers[1] = nil }, "endpoint is empty"},
		{"empty peer", 2, 6, func(m *fetch.MultiClient) { m.Peers[1].URL = " " }, "endpoint is empty"},
		{"quorum one", 2, 6, func(m *fetch.MultiClient) { m.Quorum = 1 }, "quorum"},
		{"negative quorum", 2, 6, func(m *fetch.MultiClient) { m.Quorum = -1 }, "quorum"},
		{"oversized quorum", 2, 6, func(m *fetch.MultiClient) { m.Quorum = 3 }, "quorum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := fetch.NewMultiClient([]string{srv.URL + "/a", srv.URL + "/b"})
			if tc.mutate != nil {
				tc.mutate(m)
			}
			s, err := deriveSchedule(context.Background(), m, 99, tc.from, tc.through, 1, io.Discard)
			if s != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got schedule=%v err=%v", tc.want, s != nil, err)
			}
			if calls.Load() != 0 {
				t.Fatal("invalid configuration reached RPC")
			}
		})
	}
}

func TestDeriveScheduleTerminalHeightAndLargeBatches(t *testing.T) {
	for _, batch := range []uint64{0, 1, 2, math.MaxUint64} {
		t.Run(fmt.Sprint(batch), func(t *testing.T) {
			headers, preimages := makeChain(t, 3)
			for i := range headers {
				headers[i].Height = math.MaxUint64 - 2 + uint64(i)
				if i > 0 {
					headers[i].PreviousHash = headers[i-1].HeaderHash
				}
				signFixtureHeader(&headers[i])
			}
			a := startPeer(t, headers, preimages, nil)
			defer a.Close()
			b := startPeer(t, headers, preimages, nil)
			defer b.Close()
			multi := fetch.NewMultiClient([]string{a.URL, b.URL})
			multi.Quorum = 0 // documented unanimous default
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s, err := deriveSchedule(ctx, multi, 99, math.MaxUint64-2, math.MaxUint64, batch, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Entries) != 3 || s.Entries[2].Height != math.MaxUint64 || len(s.SourcePeers) != 2 ||
				s.SourcePeers[0] != a.URL || s.SourceHeights[b.URL] != math.MaxUint64 {
				t.Fatal("schedule range or source observations changed")
			}
		})
	}
}

func TestDeriveScheduleFailurePreservesOutput(t *testing.T) {
	headers, preimages := makeChain(t, 6)
	headers[2].Signature[0] ^= 1
	urls := make([]string, 3)
	for i := range urls {
		srv := startPeer(t, headers, preimages, nil)
		t.Cleanup(srv.Close)
		urls[i] = srv.URL
	}
	path := filepath.Join(t.TempDir(), "schedule.json")
	before := []byte("previous schedule must remain intact")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"--peers", strings.Join(urls, ","), "--chain-id", "99",
		"--from", "1001", "--through", "1006", "--out", path})
	if err == nil || !strings.Contains(err.Error(), "invalid header signature") {
		t.Fatalf("expected signature error, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("derivation failure changed output: %v", err)
	}
}

func TestDeriveScheduleCommandRoundTrip(t *testing.T) {
	headers, preimages := makeChain(t, 6)
	for i := range headers {
		if i >= 2 {
			headers[i].Version = 2
			headers[i].NextFusionPrice = 1000
			headers[i].NextWorkPrice = 1000
		}
		if i > 0 {
			headers[i].PreviousHash = headers[i-1].HeaderHash
		}
		signFixtureHeader(&headers[i])
	}
	urls := make([]string, 3)
	for i := range urls {
		srv := startPeer(t, headers, preimages, nil)
		t.Cleanup(srv.Close)
		urls[i] = srv.URL
	}
	path := filepath.Join(t.TempDir(), "schedule.json")
	// Observe a subrange across both implemented layouts with higher frontiers.
	// Exporting observed signers does not prove an anchor or activation policy.
	if err := run([]string{"--peers", strings.Join(urls, ","), "--chain-id", "99",
		"--from", "1002", "--through", "1004", "--batch-size", "2", "--out", path}); err != nil {
		t.Fatal(err)
	}
	s, err := verify.LoadProducerSchedule(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Entries) != 3 || len(s.Coverage) != 1 || s.Coverage[0].FromHeight != 1002 ||
		s.Coverage[0].ThroughHeight != 1004 || s.SourceHeights[urls[0]] != 1006 {
		t.Fatal("exported range or frontier metadata differs from the observations")
	}
	auth := verify.NewScheduleAuthorizer(s)
	for _, h := range headers[1:4] {
		if auth.Authorize(h.Height, h.TimestampUnix, h.PublicKey) != verify.ProducerAuthorized {
			t.Fatalf("loaded schedule does not match observed signer at %d", h.Height)
		}
	}
	if auth.Authorize(1005, headers[4].TimestampUnix, headers[4].PublicKey) != verify.ProducerSetUnknown {
		t.Fatal("frontier metadata extended schedule coverage")
	}
}
