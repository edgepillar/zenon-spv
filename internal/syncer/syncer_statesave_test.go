package syncer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// persistenceLoop starts from six verified fixture headers, with enough
// remote history to require several catch-up batches. All RPC traffic is
// served by a local test server.
func persistenceLoop(t *testing.T) (*Loop, *bytes.Buffer, verify.HeaderState) {
	t.Helper()
	genesis, headers, preimages := chainFixtureRPC(t, 40)
	url, _, closeServer := startServer(t, headers, preimages)
	t.Cleanup(closeServer)
	policy := verify.Policy{W: 6}
	state := verify.NewHeaderState(genesis, policy)
	for _, h := range headers[:6] {
		state.Append(h)
	}
	path := tmpStateFile(t)
	if err := verify.SaveHeaderState(path, state); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	return &Loop{
		Multi: fetch.NewMultiClient([]string{url}), StatePath: path,
		Genesis: genesis, Policy: policy, SafetyMargin: 1, BatchSize: 3,
		Interval: time.Millisecond, Out: out,
	}, out, state
}

func TestRun_SaveFailuresStopWithoutAcceptOrStateAdvance(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", limit: 0, want: 3},
		{name: "configured", limit: 2, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loop, out, initial := persistenceLoop(t)
			loop.MaxStateSaveFailures = tc.limit
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			saveErr := errors.New("injected storage failure")
			var attemptedTips []uint64
			loop.SaveState = func(_ string, state verify.HeaderState) error {
				tip, _ := state.Tip()
				attemptedTips = append(attemptedTips, tip.Height)
				if len(attemptedTips) > tc.want {
					cancel() // Bound the regression case, which ignores failures.
				}
				return saveErr
			}
			if err := loop.Run(ctx); !errors.Is(err, saveErr) {
				t.Fatalf("Run error = %v, want wrapped persistence error", err)
			}
			if len(attemptedTips) != tc.want {
				t.Fatalf("save attempts = %d, want %d", len(attemptedTips), tc.want)
			}
			for _, tip := range attemptedTips {
				if tip != 1009 {
					t.Errorf("retried from unpersisted state: candidate tip = %d, want 1009", tip)
				}
			}
			if strings.Contains(out.String(), "tick: ACCEPT") {
				t.Errorf("reported ACCEPT for a failed save: %s", out.String())
			}
			loaded, err := verify.LoadHeaderState(loop.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(loaded, initial) {
				t.Error("failed saves changed persisted state")
			}
		})
	}
}

func TestRun_SaveRecoveryResetsFailureCountAndResumes(t *testing.T) {
	loop, out, _ := persistenceLoop(t)
	loop.MaxStateSaveFailures = 2
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	saveErr := errors.New("injected storage failure")
	var attemptedTips []uint64
	loop.SaveState = func(path string, state verify.HeaderState) error {
		tip, _ := state.Tip()
		attemptedTips = append(attemptedTips, tip.Height)
		if len(attemptedTips) > 4 {
			cancel()
		}
		if len(attemptedTips) == 2 {
			if strings.Contains(out.String(), "tick: ACCEPT") {
				t.Error("ACCEPT appeared before the first successful save")
			}
			return verify.SaveHeaderState(path, state)
		}
		return saveErr
	}
	if err := loop.Run(ctx); !errors.Is(err, saveErr) {
		t.Fatalf("Run error = %v, want persistence error", err)
	}
	if want := []uint64{1009, 1009, 1012, 1012}; !reflect.DeepEqual(attemptedTips, want) {
		t.Fatalf("candidate tips = %v, want %v", attemptedTips, want)
	}
	if strings.Count(out.String(), "tick: ACCEPT") != 1 ||
		!strings.Contains(out.String(), "tick: ACCEPT tip=1006 -> 1009") {
		t.Fatalf("expected only persisted progress in log: %s", out.String())
	}
	loaded, err := verify.LoadHeaderState(loop.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if tip, _ := loaded.Tip(); tip.Height != 1009 {
		t.Fatalf("persisted tip = %d, want 1009", tip.Height)
	}

	// A fresh run must extend the successful save, not either failed batch.
	resumeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	resumed := false
	loop.SaveState = func(path string, state verify.HeaderState) error {
		resumed = true
		if tip, _ := state.Tip(); tip.Height != 1012 {
			t.Errorf("resumed candidate tip = %d, want 1012", tip.Height)
		}
		err := verify.SaveHeaderState(path, state)
		stop()
		return err
	}
	if err := loop.Run(resumeCtx); err != nil {
		t.Fatal(err)
	}
	if !resumed {
		t.Fatal("restart did not resume verification")
	}
}

func TestRun_SaveFailureDoesNotTriggerImmediateCatchUp(t *testing.T) {
	loop, _, _ := persistenceLoop(t)
	loop.Interval = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	calls := 0
	var stopTimer *time.Timer
	loop.SaveState = func(string, verify.HeaderState) error {
		calls++
		if calls == 1 {
			// Start the observation interval only after the first fetch
			// and verification, so slow setup does not affect the test.
			stopTimer = time.AfterFunc(100*time.Millisecond, cancel)
		} else {
			cancel()
		}
		return errors.New("injected storage failure")
	}
	err := loop.Run(ctx)
	if stopTimer != nil {
		stopTimer.Stop()
	}
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("save attempts before next interval = %d, want 1", calls)
	}
}

type watchLogFunc func([]byte) (int, error)

func (f watchLogFunc) Write(p []byte) (int, error) { return f(p) }

func TestRun_AcceptLogFollowsPersistedState(t *testing.T) {
	loop, out, _ := persistenceLoop(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := 0
	loop.Out = watchLogFunc(func(p []byte) (int, error) {
		if strings.Contains(string(p), "tick: ACCEPT") {
			accepted++
			loaded, err := verify.LoadHeaderState(loop.StatePath)
			if err != nil {
				t.Error(err)
			} else if tip, _ := loaded.Tip(); tip.Height != 1009 {
				t.Errorf("ACCEPT precedes persistence: stored tip = %d, want 1009", tip.Height)
			}
			cancel()
		}
		return out.Write(p)
	})
	if err := loop.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if accepted != 1 {
		t.Fatalf("ACCEPT count = %d, want 1", accepted)
	}
}

func TestRun_CaughtUpSaveFailureDoesNotReportAccept(t *testing.T) {
	loop, out, _ := persistenceLoop(t)
	loop.SafetyMargin = 34 // Frontier 1040 -> target 1006, the retained tip.
	loop.MaxStateSaveFailures = 1
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	saveErr := errors.New("injected storage failure")
	loop.SaveState = func(string, verify.HeaderState) error {
		cancel()
		return saveErr
	}
	if err := loop.Run(ctx); !errors.Is(err, saveErr) {
		t.Fatalf("Run error = %v, want persistence error", err)
	}
	if strings.Contains(out.String(), "tick: ACCEPT") {
		t.Errorf("reported caught-up ACCEPT before saving: %s", out.String())
	}
}

func TestRun_NegativeSaveFailureLimitIsRejected(t *testing.T) {
	loop, _, _ := persistenceLoop(t)
	loop.MaxStateSaveFailures = -1
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := loop.Run(ctx); err == nil || !strings.Contains(err.Error(), "MaxStateSaveFailures") {
		t.Fatalf("invalid limit error = %v", err)
	}
}

func TestRun_RefusedTickDoesNotSave(t *testing.T) {
	loop, out, _ := persistenceLoop(t)
	loop.Policy.MaxHeaders = 1
	_, headers, preimages := chainFixtureRPC(t, 40)
	// The peer ignores the one-header request and sends an extra header.
	url, _, closeServer := startServer(t, headers, preimages, 1007)
	defer closeServer()
	loop.Multi = fetch.NewMultiClient([]string{url})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	loop.SaveState = func(string, verify.HeaderState) error {
		t.Error("REFUSED tick attempted persistence")
		cancel()
		return fmt.Errorf("unexpected save")
	}
	loop.Out = watchLogFunc(func(p []byte) (int, error) {
		if strings.Contains(string(p), "tick: REFUSED") {
			cancel()
		}
		return out.Write(p)
	})
	if err := loop.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "tick: REFUSED ReasonMissingEvidence") ||
		!strings.Contains(out.String(), "response does not match query") {
		t.Fatalf("expected refusal of the oversized RPC response: %s", out.String())
	}
}
