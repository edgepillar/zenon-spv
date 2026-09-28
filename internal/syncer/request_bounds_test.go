package syncer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type rangeRequestRecorder struct {
	transport http.RoundTripper
	mu        sync.Mutex
	counts    []uint64
}

func (r *rangeRequestRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.GetBody == nil {
		return nil, errors.New("test request body is not replayable")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()
	var wire struct {
		Method string   `json:"method"`
		Params []uint64 `json:"params"`
	}
	if err := json.NewDecoder(body).Decode(&wire); err != nil {
		return nil, err
	}
	if wire.Method == "ledger.getMomentumsByHeight" {
		if len(wire.Params) != 2 {
			return nil, errors.New("unexpected test range parameters")
		}
		r.mu.Lock()
		r.counts = append(r.counts, wire.Params[1])
		r.mu.Unlock()
	}
	return r.transport.RoundTrip(req)
}

func TestTickCapsRPCRequestsByVerifierPolicy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		limit       int
		batch, want uint64
	}{
		{"policy cap", 4, 100, 4}, {"smaller batch", 4, 2, 2},
		{"uncapped internal batch", 4, 0, 4}, {"single header", 1, math.MaxUint64, 1},
		{"disabled policy cap", 0, 10, 10}, {"remaining range", 100, math.MaxUint64, 33},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loop, _, _ := persistenceLoop(t)
			loop.Policy.MaxHeaders, loop.BatchSize = tc.limit, tc.batch
			client := loop.Multi.Peers[0].HTTP
			recorder := &rangeRequestRecorder{transport: client.Transport}
			client.Transport = recorder
			state, err := verify.LoadTrustedState(loop.StatePath, loop.Genesis, verify.VerifyOptions{Policy: loop.Policy})
			if err != nil {
				t.Fatal(err)
			}
			before, _ := state.Tip()
			result, next := loop.tick(context.Background(), state)
			if result.Outcome != verify.OutcomeAccept || uint64(len(result.FetchedHeights)) != tc.want {
				t.Fatalf("policy-sized batch did not advance: outcome=%s fetched=%d want=%d", result.Outcome, len(result.FetchedHeights), tc.want)
			}
			recorder.mu.Lock()
			counts := append([]uint64(nil), recorder.counts...)
			recorder.mu.Unlock()
			if len(counts) != 2 || counts[0] != 1 || counts[1] != tc.want {
				t.Fatalf("RPC request counts=%v, want [1 %d]", counts, tc.want)
			}
			tip, _ := next.Tip()
			original, _ := state.Tip()
			if tip.Height != before.Height+tc.want || original.Height != before.Height {
				t.Fatal("wrong advancement or predecessor mutation")
			}
		})
	}
}

func TestRunPersistsPolicySizedBatchWithExplicitOrDefaultOptions(t *testing.T) {
	for _, batch := range []uint64{0, 100} {
		loop, out, _ := persistenceLoop(t)
		loop.Policy.MaxHeaders, loop.BatchSize = 4, batch
		loop.Interval, loop.SafetyMargin = 0, 0
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		saves := 0
		loop.SaveState = func(path string, state verify.HeaderState) error {
			saves++
			err := verify.SaveHeaderState(path, state)
			cancel()
			return err
		}
		err := loop.Run(ctx)
		cancel()
		if err != nil || saves != 1 || !strings.Contains(out.String(), "tick: ACCEPT tip=1006 -> 1010 (fetched 4,") {
			t.Fatalf("policy cap stalled watch: err=%v saves=%d log=%s", err, saves, out.String())
		}
		state, err := verify.LoadTrustedState(loop.StatePath, loop.Genesis, verify.VerifyOptions{Policy: loop.Policy})
		if err != nil {
			t.Fatal(err)
		}
		if tip, ok := state.Tip(); !ok || tip.Height != 1010 {
			t.Fatal("policy-sized batch was not persisted")
		}
		if loop.Interval != 10*time.Second || loop.SafetyMargin != 6 || (batch == 0 && loop.BatchSize != 60) {
			t.Fatal("zero-valued watch options lost their documented defaults")
		}
	}
}

func TestRunRejectsNegativeIntervalBeforeState(t *testing.T) {
	path := tmpStateFile(t)
	before := []byte("state must not be read or replaced")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	loop := &Loop{Multi: fetch.NewMultiClient([]string{"http://127.0.0.1:1"}), StatePath: path,
		Interval: -time.Nanosecond, Out: &out, ShowContext: true}
	err := loop.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Interval must not be negative") || out.Len() != 0 {
		t.Fatalf("negative interval reached state or startup reporting: err=%v log=%s", err, out.String())
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("negative interval changed state: %v", err)
	}
}
