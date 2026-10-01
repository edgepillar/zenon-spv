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

func decodeWatchEvent(t *testing.T, p []byte) watchEvent {
	t.Helper()
	if len(p) == 0 || p[len(p)-1] != '\n' || bytes.Count(p, []byte{'\n'}) != 1 {
		t.Fatal("watch output is not one complete JSON line")
	}
	var event watchEvent
	decoder := json.NewDecoder(bytes.NewReader(p))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.SchemaVersion != 1 || event.Command != "watch" || event.Context.Fingerprint == nil ||
		!slices.Contains(event.StateTrust, verify.TrustConfiguredAnchor) ||
		!slices.Contains(event.StateTrust, verify.TrustPersistedState) ||
		!slices.Equal(event.SourceTrust, []verify.TrustAssumption{verify.TrustRPCQuorum}) || len(event.Caveats) == 0 {
		t.Fatal("event omitted its version, context, or trust boundaries")
	}
	if bytes.Contains(bytes.ToUpper(p), []byte("PRIVATE")) {
		t.Fatal("event disclosed private source or error data")
	}
	return event
}

func TestWatchJSONEventsRespectVerificationAndPersistence(t *testing.T) {
	for _, mode := range []string{"advance", "caught up", "rejected", "fetch refused", "frontier refused", "save failed", "save failed after replacement"} {
		t.Run(mode, func(t *testing.T) {
			loop, _, _ := persistenceLoop(t)
			loop.JSON, loop.ShowContext, loop.MaxStateSaveFailures = true, true, 1
			loop.Multi.Quorum = 0 // The startup report must show the effective quorum.
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
					http.Error(w, "PRIVATE_REMOTE_RESPONSE", http.StatusServiceUnavailable)
				}))
				t.Cleanup(server.Close)
				loop.Multi = fetch.NewMultiClient([]string{server.URL + "/PRIVATE_ENDPOINT"})
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var events []watchEvent
			saves := 0
			saveErr := errors.New("PRIVATE_STORAGE_PATH")
			loop.SaveState = func(path string, snapshot verify.HeaderState) error {
				saves++
				if len(events) != 1 || events[0].Event != "started" {
					t.Error("tick was reported before saving")
				}
				if mode == "save failed" {
					return saveErr
				}
				if err := verify.SaveHeaderState(path, snapshot); err != nil {
					return err
				}
				if mode == "save failed after replacement" {
					return saveErr
				}
				return nil
			}
			loop.Out = watchLogFunc(func(p []byte) (int, error) {
				event := decodeWatchEvent(t, p)
				events = append(events, event)
				if event.Event != "started" {
					if event.Persistence == "saved" {
						stored, err := verify.LoadHeaderState(loop.StatePath)
						if err != nil {
							t.Error(err)
						} else if tip, _ := stored.Tip(); tip.Height != event.StateTip.Height || tip.HeaderHash != event.StateTip.Hash {
							t.Error("saved event did not follow persistence of its exact tip")
						}
					}
					cancel()
				}
				return len(p), nil
			})
			err := loop.Run(ctx)
			failedSave := strings.HasPrefix(mode, "save failed")
			if failedSave && !errors.Is(err, saveErr) || !failedSave && err != nil || len(events) != 2 {
				t.Fatalf("unexpected watch completion: %v; events=%d", err, len(events))
			}
			started, tick := events[0], events[1]
			if started.Event != "started" || started.Settings == nil || started.Settings.Quorum != 1 || started.Settings.MaxStateSaveFailures != 1 ||
				started.Persistence != "not_attempted" || started.Verification != nil || started.CandidateTip != nil || started.TargetHeight != nil || started.Reason != nil {
				t.Fatal("startup falsely described a completed tick")
			}
			if tick.Settings != nil || tick.PreviousTipHeight == nil || *tick.PreviousTipHeight != 1006 || tick.Reason == nil {
				t.Fatal("tick omitted its starting point or repeated startup settings")
			}
			wantTip, wantFileTip, wantSaves := uint64(1006), uint64(1006), 1
			switch mode {
			case "advance":
				wantTip, wantFileTip = 1009, 1009
				if tick.Event != "advanced" || tick.Persistence != "saved" || tick.CandidateTip == nil || tick.CandidateTip.Height != 1009 {
					t.Fatal("saved progress was not reported")
				}
			case "caught up":
				if tick.Event != "caught_up" || tick.Persistence != "saved" || tick.Verification != nil || tick.CandidateTip != nil || tick.FetchedCount != 0 {
					t.Fatal("caught-up status invented a header verification")
				}
			case "rejected":
				wantSaves = 0
				if tick.Event != "rejected" || tick.Persistence != "not_attempted" || tick.Verification == nil || tick.Verification.Outcome != "REJECT" || tick.Verification.Reason != "ReasonInvalidSignature" || tick.CandidateTip != nil {
					t.Fatal("rejected batch was hidden or described as saved")
				}
			case "fetch refused", "frontier refused":
				wantSaves = 0
				stage := strings.Fields(mode)[0]
				if tick.Event != "refused" || tick.Persistence != "not_attempted" || tick.Verification != nil || tick.CandidateTip != nil || tick.Error == nil || tick.Error.Stage != stage || tick.Error.Category != "quorum_unavailable" {
					t.Fatal("unavailable evidence invented verification or lost its stage")
				}
				if (tick.TargetHeight == nil) != (stage == "frontier") {
					t.Fatal("target availability was misreported")
				}
			default:
				if tick.Event != "save_failed" || tick.Persistence != "failed" || tick.ConsecutiveSaveFailures != 1 || tick.Error == nil || tick.Error.Stage != "persistence" || tick.CandidateTip == nil || tick.CandidateTip.Height != 1009 {
					t.Fatal("save failure claimed completed progress or lost its candidate")
				}
				if mode == "save failed after replacement" {
					wantFileTip = 1009
				}
			}
			if mode == "advance" || failedSave {
				v := tick.Verification
				if v == nil || v.Outcome != "ACCEPT" || tick.FetchedCount != 3 || !slices.Contains(v.Proven, verify.GuaranteeHeaderChainIntegrity) ||
					slices.Contains(v.Proven, verify.GuaranteeCanonicality) || !slices.Contains(v.NotProven, verify.GuaranteeCanonicality) ||
					!slices.Contains(v.TrustAssumptions, verify.TrustPersistedState) {
					t.Fatal("verification guarantees were omitted or overstated")
				}
			}
			if tick.StateTip.Height != wantTip || saves != wantSaves {
				t.Fatal("event crossed the retained-state persistence boundary")
			}
			stored, err := verify.LoadHeaderState(loop.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			if tip, _ := stored.Tip(); tip.Height != wantFileTip {
				t.Fatal("event handling changed the stored tip")
			}
			if saves == 0 || mode == "save failed" {
				unchanged()
			}
			checkWatchOutputLockReleased(t, loop.StatePath)
		})
	}
}

func TestWatchJSONOutputFailureStopsWithoutRetry(t *testing.T) {
	for _, stage := range []string{"started", "advanced", "save_failed"} {
		for _, short := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/short=%t", stage, short), func(t *testing.T) {
				loop, _, _ := persistenceLoop(t)
				loop.JSON = true
				var requests atomic.Int64
				if stage == "started" {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1) }))
					t.Cleanup(server.Close)
					loop.Multi = fetch.NewMultiClient([]string{server.URL})
				}
				unchanged := protectWatchOutputState(t, loop.StatePath)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				outputErr, saveErr := errors.New("PRIVATE_WRITER"), errors.New("PRIVATE_STORAGE")
				if short {
					outputErr = io.ErrShortWrite
				}
				saves, failed, laterWrites := 0, false, 0
				loop.SaveState = func(path string, snapshot verify.HeaderState) error {
					saves++
					if stage == "save_failed" {
						return saveErr
					}
					return verify.SaveHeaderState(path, snapshot)
				}
				loop.Out = watchLogFunc(func(p []byte) (int, error) {
					if failed {
						laterWrites++
					}
					if event := decodeWatchEvent(t, p); event.Event == stage {
						failed = true
						cancel()
						if short {
							return len(p) - 1, nil
						}
						return 0, outputErr
					}
					return len(p), nil
				})
				if err := loop.Run(ctx); !errors.Is(err, outputErr) || errors.Is(err, saveErr) != (stage == "save_failed") {
					t.Fatalf("event output failure lost its causes: %v", err)
				}
				if !failed || laterWrites != 0 || requests.Load() != 0 || stage == "started" && saves != 0 || stage != "started" && saves != 1 {
					t.Fatal("output failure did not stop subsequent work")
				}
				if stage != "advanced" {
					unchanged()
				} else {
					stored, err := verify.LoadHeaderState(loop.StatePath)
					if err != nil {
						t.Fatal(err)
					}
					if tip, _ := stored.Tip(); tip.Height != 1009 {
						t.Fatal("lost output rolled back completed progress")
					}
				}
				checkWatchOutputLockReleased(t, loop.StatePath)
			})
		}
	}
}

func TestWatchJSONSaveRecoveryRetainsAttemptBoundaries(t *testing.T) {
	loop, output, _ := persistenceLoop(t)
	loop.JSON, loop.MaxStateSaveFailures = true, 2
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	attempts := 0
	saveErr := errors.New("PRIVATE_STORAGE_FAILURE")
	loop.SaveState = func(path string, snapshot verify.HeaderState) error {
		attempts++
		if attempts == 2 {
			return verify.SaveHeaderState(path, snapshot)
		}
		return saveErr
	}
	if err := loop.Run(ctx); !errors.Is(err, saveErr) || attempts != 4 {
		t.Fatalf("save recovery lost its bounded failure sequence: %v", err)
	}
	lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
	if len(lines) != 5 {
		t.Fatal("save recovery omitted or duplicated events")
	}
	for i, want := range []struct {
		event     string
		retained  uint64
		candidate uint64
		failures  int
	}{
		{"save_failed", 1006, 1009, 1},
		{"advanced", 1009, 1009, 0},
		{"save_failed", 1009, 1012, 1},
		{"save_failed", 1009, 1012, 2},
	} {
		e := decodeWatchEvent(t, append(slices.Clone(lines[i+1]), '\n'))
		if e.Event != want.event || e.StateTip.Height != want.retained || e.CandidateTip == nil || e.CandidateTip.Height != want.candidate || e.ConsecutiveSaveFailures != want.failures {
			t.Fatalf("event %d misrepresented save recovery", i+1)
		}
	}
	checkWatchOutputLockReleased(t, loop.StatePath)
}
