package syncer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestRunOnceCompletesOneBoundedTick(t *testing.T) {
	for _, mode := range []string{"advance", "caught up", "rejected", "fetch refused", "frontier refused", "save failed", "save failed after replacement"} {
		for _, jsonOutput := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%t", mode, jsonOutput), func(t *testing.T) {
				loop, output, _ := persistenceLoop(t)
				loop.JSON, loop.Interval = jsonOutput, time.Hour
				loop.MaxStateSaveFailures = 9 // RunOnce must still attempt only one save.
				unchanged := protectWatchOutputState(t, loop.StatePath)
				if mode == "caught up" {
					loop.SafetyMargin = 34
				}
				if mode == "rejected" || mode == "fetch refused" {
					_, headers, preimages := chainFixtureRPC(t, 40)
					var extra []uint64
					if mode == "rejected" {
						headers[6].Signature[0] ^= 1
					} else {
						extra = []uint64{1007}
					}
					url, _, closeServer := startServer(t, headers, preimages, extra...)
					t.Cleanup(closeServer)
					loop.Multi = fetch.NewMultiClient([]string{url})
				}
				if mode == "frontier refused" {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						http.Error(w, "PRIVATE_RPC_FAILURE", http.StatusServiceUnavailable)
					}))
					t.Cleanup(server.Close)
					loop.Multi = fetch.NewMultiClient([]string{server.URL})
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				storageErr := errors.New("PRIVATE_STORAGE_FAILURE")
				saves := 0
				loop.SaveState = func(path string, snapshot verify.HeaderState) error {
					saves++
					if mode == "save failed" {
						return storageErr
					}
					if err := verify.SaveHeaderState(path, snapshot); err != nil {
						return err
					}
					if mode == "save failed after replacement" {
						return storageErr
					}
					return nil
				}
				result, err := loop.RunOnce(ctx)
				failedSave := strings.HasPrefix(mode, "save failed")
				if ctx.Err() != nil || errors.Is(err, storageErr) != failedSave || !failedSave && err != nil {
					t.Fatalf("single-step run retried, waited, or lost its error: %v", err)
				}
				wantOutcome, wantSaves, wantTip := verify.OutcomeAccept, 1, uint64(1006)
				switch mode {
				case "advance", "save failed after replacement":
					wantTip = 1009
				case "rejected":
					wantOutcome, wantSaves = verify.OutcomeReject, 0
				case "fetch refused", "frontier refused":
					wantOutcome, wantSaves = verify.OutcomeRefused, 0
				}
				if result.Outcome != wantOutcome || result.Tip != 1006 || saves != wantSaves {
					t.Fatalf("single-step result or save count is incorrect: %+v; saves=%d", result, saves)
				}
				if mode == "advance" && (result.Target != 1039 || !slices.Equal(result.FetchedHeights, []uint64{1007, 1008, 1009})) {
					t.Fatal("single-step run exceeded one bounded batch or hid the remaining target")
				}
				stored, err := verify.LoadHeaderState(loop.StatePath)
				if err != nil {
					t.Fatal(err)
				}
				if tip, _ := stored.Tip(); tip.Height != wantTip {
					t.Fatal("single-step run persisted beyond its allowed batch")
				}
				if wantSaves == 0 || mode == "save failed" {
					unchanged()
				}
				if jsonOutput {
					lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
					if len(lines) != 2 {
						t.Fatal("single-step JSON emitted more than startup and one tick")
					}
					started := decodeWatchEvent(t, append(slices.Clone(lines[0]), '\n'))
					tick := decodeWatchEvent(t, append(slices.Clone(lines[1]), '\n'))
					if started.Settings == nil || started.Settings.MaxStateSaveFailures != 1 || failedSave && tick.Event != "save_failed" {
						t.Fatal("single-step events misrepresented save limits or persistence")
					}
				} else if failedSave && strings.Contains(output.String(), "tick: ACCEPT") {
					t.Fatal("failed single-step save reported completed progress")
				}
				checkWatchOutputLockReleased(t, loop.StatePath)
			})
		}
	}
}

func TestRunOnceCancellationBeforeTickDoesNotSucceed(t *testing.T) {
	loop, _, _ := persistenceLoop(t)
	unchanged := protectWatchOutputState(t, loop.StatePath)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1) }))
	t.Cleanup(server.Close)
	loop.Multi = fetch.NewMultiClient([]string{server.URL})
	saves := 0
	loop.SaveState = func(string, verify.HeaderState) error { saves++; return nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := loop.RunOnce(ctx)
	if !errors.Is(err, context.Canceled) || result.Outcome == verify.OutcomeAccept || calls.Load() != 0 || saves != 0 {
		t.Fatal("cancellation reported a successful empty step or started work")
	}
	unchanged()
	checkWatchOutputLockReleased(t, loop.StatePath)
}

func TestRunOnceOutputFailureTakesPrecedence(t *testing.T) {
	for _, stage := range []string{"started", "advanced", "save_failed"} {
		for _, short := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/short=%t", stage, short), func(t *testing.T) {
				loop, _, _ := persistenceLoop(t)
				loop.JSON = true
				unchanged := protectWatchOutputState(t, loop.StatePath)
				writerErr, storageErr := errors.New("PRIVATE_WRITER"), errors.New("PRIVATE_STORAGE")
				if short {
					writerErr = io.ErrShortWrite
				}
				saves := 0
				loop.SaveState = func(path string, snapshot verify.HeaderState) error {
					saves++
					if stage == "save_failed" {
						return storageErr
					}
					return verify.SaveHeaderState(path, snapshot)
				}
				writes, failed := 0, false
				loop.Out = watchLogFunc(func(p []byte) (int, error) {
					writes++
					if failed {
						t.Error("single-step run retried failed output")
					}
					var e struct{ Event string }
					if err := json.Unmarshal(p, &e); err != nil {
						t.Fatal(err)
					}
					if e.Event == stage {
						failed = true
						if short {
							return len(p) - 1, nil
						}
						return 0, writerErr
					}
					return len(p), nil
				})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				result, err := loop.RunOnce(ctx)
				if !errors.Is(err, writerErr) || errors.Is(err, storageErr) != (stage == "save_failed") || !failed {
					t.Fatalf("single-step output error lost a cause: %v", err)
				}
				if stage == "started" {
					if result.Outcome == verify.OutcomeAccept || saves != 0 || writes != 1 {
						t.Fatal("failed startup reported an accepted tick or saved state")
					}
				} else if result.Outcome != verify.OutcomeAccept || saves != 1 || writes != 2 {
					t.Fatal("completed verification was lost or repeated after output failure")
				}
				if stage != "advanced" {
					unchanged()
				} else {
					stored, loadErr := verify.LoadHeaderState(loop.StatePath)
					if tip, _ := stored.Tip(); loadErr != nil || tip.Height != 1009 {
						t.Fatal("output failure rolled back a completed single-step save")
					}
				}
				checkWatchOutputLockReleased(t, loop.StatePath)
			})
		}
	}
}
