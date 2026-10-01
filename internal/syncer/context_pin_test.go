package syncer

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/statelock"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestWatchContextPinStopsBeforeRPCAndPersistence(t *testing.T) {
	for _, custom := range []bool{false, true} {
		for _, once := range []bool{false, true} {
			loop, out, _ := persistenceLoop(t)
			loop.JSON = true
			loop.ExpectedContext = &chain.Hash{}
			want := verify.ErrContextFingerprintMismatch
			if custom {
				loop.Authorizer = contextTestAuthorizer{}
				want = verify.ErrContextFingerprintUnavailable
			}
			before, err := os.ReadFile(loop.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int32
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			loop.Multi = fetch.NewMultiClient([]string{peer.URL})
			saves := 0
			loop.SaveState = func(string, verify.HeaderState) error { saves++; return nil }
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			if once {
				_, err = loop.RunOnce(ctx)
			} else {
				err = loop.Run(ctx)
			}
			cancel()
			peer.Close()
			if !errors.Is(err, want) || requests.Load() != 0 || saves != 0 || out.Len() != 0 {
				t.Fatalf("pin failure reached startup, RPC, or persistence: %v", err)
			}
			after, err := os.ReadFile(loop.StatePath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("pin failure changed saved state")
			}
			lock, err := statelock.Acquire(loop.StatePath)
			if err != nil {
				t.Fatal("pin failure retained writer ownership")
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestWatchMatchingContextPinAllowsAdvanceAndResume(t *testing.T) {
	loop, _, _ := persistenceLoop(t)
	opts := verify.VerifyOptions{Policy: loop.Policy}
	state, err := verify.LoadTrustedState(loop.StatePath, loop.Genesis, opts)
	if err != nil {
		t.Fatal(err)
	}
	view, err := state.VerificationContext()
	if err != nil {
		t.Fatal(err)
	}
	loop.ExpectedContext = view.Fingerprint
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, height := range []uint64{1009, 1012} {
		result, err := loop.RunOnce(ctx)
		if err != nil || result.Outcome != verify.OutcomeAccept {
			t.Fatalf("matching pin prevented bounded progress: %v", err)
		}
		saved, err := verify.LoadTrustedState(loop.StatePath, loop.Genesis, opts)
		if err != nil {
			t.Fatal(err)
		}
		tip, ok := saved.Tip()
		if !ok || tip.Height != height || saved.RequireContextFingerprint(*view.Fingerprint) != nil {
			t.Fatal("pinned watch did not persist the expected next batch")
		}
	}
}
