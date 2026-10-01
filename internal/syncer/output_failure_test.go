package syncer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/statelock"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestRunReturnsStartupOutputFailure(t *testing.T) {
	for _, stage := range []string{"watching:", "state: trust_assumptions=", "verification_context:"} {
		for _, short := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/short=%t", stage, short), func(t *testing.T) {
				loop, _, _ := persistenceLoop(t)
				loop.ShowContext = true
				unchanged := protectWatchOutputState(t, loop.StatePath)
				var requests atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					requests.Add(1)
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				defer server.Close()
				loop.Multi = fetch.NewMultiClient([]string{server.URL})
				saves := 0
				loop.SaveState = func(string, verify.HeaderState) error { saves++; return errors.New("unexpected save") }
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				outputErr := errors.New("private-output-failure")
				if short {
					outputErr = io.ErrShortWrite
				}
				failed, laterWrites := false, 0
				loop.Out = watchLogFunc(func(p []byte) (int, error) {
					if failed {
						laterWrites++
						return 0, outputErr
					}
					if strings.HasPrefix(string(p), stage) {
						failed = true
						cancel() // Bound the old implementation, which ignores the error.
						if short {
							return len(p) - 1, nil
						}
						return 0, outputErr
					}
					return len(p), nil
				})
				if err := loop.Run(ctx); !errors.Is(err, outputErr) || strings.Contains(err.Error(), "private-output") {
					t.Fatalf("startup output failure was ignored: %v", err)
				}
				if !failed || laterWrites != 0 || requests.Load() != 0 || saves != 0 {
					t.Fatal("startup output failure continued reporting, RPC, or persistence")
				}
				unchanged()
				checkWatchOutputLockReleased(t, loop.StatePath)
			})
		}
	}
}

func TestRunReturnsOutputFailureAfterPersistingProgress(t *testing.T) {
	loop, _, _ := persistenceLoop(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outputErr := errors.New("private-output-failure")
	saves := 0
	loop.SaveState = func(path string, state verify.HeaderState) error {
		saves++
		return verify.SaveHeaderState(path, state)
	}
	loop.Out = watchLogFunc(func(p []byte) (int, error) {
		if strings.HasPrefix(string(p), "tick: ACCEPT") {
			cancel()
			return 0, outputErr
		}
		return len(p), nil
	})
	if err := loop.Run(ctx); !errors.Is(err, outputErr) {
		t.Fatalf("accepted tick output failure was ignored: %v", err)
	}
	if saves != 1 {
		t.Fatalf("output failure allowed repeated catch-up saves: %d", saves)
	}
	state, err := verify.LoadTrustedState(loop.StatePath, loop.Genesis, verify.VerifyOptions{Policy: loop.Policy})
	if err != nil {
		t.Fatal(err)
	}
	if tip, _ := state.Tip(); tip.Height != 1009 {
		t.Fatal("output failure rolled back already persisted progress")
	}
	checkWatchOutputLockReleased(t, loop.StatePath)
	// A fresh run resumes the completed save even though its report was lost.
	resumeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	loop.Out = nil // Explicitly discarding output remains supported.
	loop.SaveState = func(path string, state verify.HeaderState) error {
		saves++
		if tip, _ := state.Tip(); tip.Height != 1012 {
			t.Error("restart did not extend the last completed save")
		}
		err := verify.SaveHeaderState(path, state)
		stop()
		return err
	}
	if err := loop.Run(resumeCtx); err != nil || saves != 2 {
		t.Fatalf("restart after an output failure did not complete one save: %v", err)
	}
}

func TestRunOutputFailuresAcrossTickOutcomes(t *testing.T) {
	for _, mode := range []string{"advance", "caught up", "rejected", "refused", "save failure"} {
		for _, short := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/short=%t", mode, short), func(t *testing.T) {
				loop, _, _ := persistenceLoop(t)
				unchanged := protectWatchOutputState(t, loop.StatePath)
				prefix := "tick: ACCEPT"
				if mode == "caught up" {
					loop.SafetyMargin = 34
					prefix = "tick: ACCEPT (caught up"
				}
				if mode == "rejected" || mode == "refused" {
					_, headers, preimages := chainFixtureRPC(t, 40)
					var extra []uint64
					if mode == "rejected" {
						headers[6].Signature[0] ^= 1
						prefix = "tick: REJECT"
					} else {
						extra = []uint64{1007}
						prefix = "tick: REFUSED"
					}
					url, _, closeServer := startServer(t, headers, preimages, extra...)
					t.Cleanup(closeServer)
					loop.Multi = fetch.NewMultiClient([]string{url})
				}
				if mode == "save failure" {
					prefix = "state: save failed"
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				outputErr := errors.New("private-output-failure")
				if short {
					outputErr = io.ErrShortWrite
				}
				failed, laterWrites := false, 0
				loop.Out = watchLogFunc(func(p []byte) (int, error) {
					if failed {
						laterWrites++
						return 0, outputErr
					}
					if strings.HasPrefix(string(p), prefix) {
						failed = true
						cancel()
						if short {
							return len(p) - 1, nil
						}
						return 0, outputErr
					}
					return len(p), nil
				})
				saveErr := errors.New("injected storage failure")
				saves := 0
				loop.SaveState = func(path string, state verify.HeaderState) error {
					saves++
					if mode == "save failure" {
						return saveErr
					}
					return verify.SaveHeaderState(path, state)
				}
				err := loop.Run(ctx)
				if !errors.Is(err, outputErr) || strings.Contains(err.Error(), "private-output") || !failed || laterWrites != 0 {
					t.Fatalf("tick output failure was ignored, retried, or disclosed a writer value: %v", err)
				}
				if (mode == "save failure") != errors.Is(err, saveErr) {
					t.Fatal("combined persistence/output failure lost a cause")
				}
				wantSaves, wantTip := 1, uint64(1006)
				if mode == "advance" {
					wantTip = 1009
				}
				if mode == "rejected" || mode == "refused" {
					wantSaves = 0
				}
				if mode == "rejected" || mode == "refused" || mode == "save failure" {
					unchanged()
				}
				state, err := verify.LoadTrustedState(loop.StatePath, loop.Genesis, verify.VerifyOptions{Policy: loop.Policy})
				if err != nil {
					t.Fatal(err)
				}
				if tip, _ := state.Tip(); tip.Height != wantTip || saves != wantSaves {
					t.Fatal("output failure changed the persistence boundary")
				}
				checkWatchOutputLockReleased(t, loop.StatePath)
			})
		}
	}
}

func protectWatchOutputState(t *testing.T, path string) func() {
	t.Helper()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("output failure rewrote state bytes")
		}
		current, err := os.Stat(path)
		if err != nil || !os.SameFile(info, current) || info.Mode() != current.Mode() || !info.ModTime().Equal(current.ModTime()) {
			t.Fatal("output failure replaced or changed state metadata")
		}
	}
}

func checkWatchOutputLockReleased(t *testing.T, path string) {
	t.Helper()
	lock, err := statelock.Acquire(path)
	if err != nil {
		t.Fatalf("output failure retained writer ownership: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

// Embedding a buffer promotes WriteString, but an override of Write may carry
// required accounting, cancellation, or failure behavior for the configured Out.
type embeddedWatchOutput struct {
	bytes.Buffer
	err    error
	writes int
}

func (w *embeddedWatchOutput) Write([]byte) (int, error) {
	w.writes++
	return 0, w.err
}

func TestRunDoesNotBypassConfiguredWriter(t *testing.T) {
	loop, _, _ := persistenceLoop(t)
	unchanged := protectWatchOutputState(t, loop.StatePath)
	w := &embeddedWatchOutput{err: errors.New("injected writer failure")}
	loop.Out = w
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := loop.Run(ctx); !errors.Is(err, w.err) || w.writes != 1 || w.Len() != 0 {
		t.Fatalf("promoted WriteString bypassed the configured Write method: writes=%d err=%v", w.writes, err)
	}
	unchanged()
	checkWatchOutputLockReleased(t, loop.StatePath)
}
