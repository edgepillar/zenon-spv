package syncer

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestRunInvalidPeerConfigStopsBeforeStateOrRPC(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	peer := fetch.NewClient(server.URL)
	for name, multi := range map[string]*fetch.MultiClient{
		"empty": {}, "negative quorum": {Peers: []*fetch.Client{peer}, Quorum: -1},
		"excessive quorum": {Peers: []*fetch.Client{peer}, Quorum: 2},
		"nil peer":         {Peers: []*fetch.Client{peer, nil}, Quorum: 1},
	} {
		t.Run(name, func(t *testing.T) {
			path := tmpStateFile(t)
			before := []byte("state must not be read or replaced")
			if err := os.WriteFile(path, before, 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			saves := 0
			loop := &Loop{Multi: multi, StatePath: path, Out: &out, ShowContext: true,
				SaveState: func(string, verify.HeaderState) error { saves++; return nil }}
			if err := loop.Run(context.Background()); !errors.Is(err, fetch.ErrInvalidPeerConfiguration) {
				t.Fatalf("invalid peer setup did not fail first: %v", err)
			}
			if requests.Load() != 0 || saves != 0 || out.Len() != 0 {
				t.Fatal("invalid peer setup reached RPC, persistence, or startup reporting")
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(before, after) {
				t.Fatalf("invalid peer setup changed state: %v", err)
			}
		})
	}
}

func TestRunZeroQuorumOutagePreservesState(t *testing.T) {
	loop, out, _ := persistenceLoop(t)
	before, err := os.ReadFile(loop.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		cancel()
	}))
	defer server.Close()
	loop.Multi = fetch.NewMultiClient([]string{server.URL})
	loop.Multi.Quorum = 0
	saves := 0
	loop.SaveState = func(string, verify.HeaderState) error { saves++; return nil }
	if err := loop.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != context.Canceled || requests.Load() == 0 {
		t.Fatal("test did not reach the unavailable RPC peer")
	}
	if saves != 0 || strings.Contains(out.String(), "tick: ACCEPT") || !strings.Contains(out.String(), "tick: REFUSED") {
		t.Fatalf("unavailable unanimous quorum advanced state: saves=%d log=%s", saves, out.String())
	}
	if after, err := os.ReadFile(loop.StatePath); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("unavailable quorum changed persisted state: %v", err)
	}
	if loop.Multi.Quorum != 0 {
		t.Fatal("watch mutated the supplied quorum")
	}
}
