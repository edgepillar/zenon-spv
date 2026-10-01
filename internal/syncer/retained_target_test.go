package syncer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestWatchCaughtUpRequiresRetainedTargetIdentity(t *testing.T) {
	for _, mode := range []string{"same tip", "same older header", "different hash", "different signer", "different signature", "evicted height"} {
		for _, once := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/once=%t", mode, once), func(t *testing.T) {
				loop, output, _ := persistenceLoop(t)
				loop.JSON, loop.Interval, loop.SafetyMargin = true, time.Hour, 34
				_, headers, preimages := chainFixtureRPC(t, 40)
				switch mode {
				case "same older header":
					loop.SafetyMargin = 35
				case "different hash":
					headers[5].TimestampUnix++
					headers[5].HeaderHash = headers[5].ComputeHash()
					headers[5].Signature = ed25519.Sign(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), headers[5].HeaderHash[:])
				case "different signer":
					seed := make([]byte, ed25519.SeedSize)
					seed[0] = 1
					key := ed25519.NewKeyFromSeed(seed)
					headers[5].PublicKey = key.Public().(ed25519.PublicKey)
					headers[5].Signature = ed25519.Sign(key, headers[5].HeaderHash[:])
				case "different signature":
					headers[5].Signature[0] ^= 1
				case "evicted height":
					// Resume narrows the retained range to 1005..1006. The
					// remote target 1004 no longer has a local comparison point.
					loop.Policy.W, loop.SafetyMargin = 1, 36
				}
				url, _, closeServer := startServer(t, headers, preimages)
				t.Cleanup(closeServer)
				secondURL, _, closeSecondServer := startServer(t, headers, preimages)
				t.Cleanup(closeSecondServer)
				loop.Multi = fetch.NewMultiClient([]string{url, secondURL})
				unchanged := protectWatchOutputState(t, loop.StatePath)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				loop.Out = watchLogFunc(func(p []byte) (int, error) {
					n, err := output.Write(p)
					if bytes.Count(output.Bytes(), []byte{'\n'}) == 2 {
						cancel()
					}
					return n, err
				})
				saves := 0
				loop.SaveState = func(path string, state verify.HeaderState) error {
					saves++
					return verify.SaveHeaderState(path, state)
				}
				var result TickResult
				var err error
				if once {
					result, err = loop.RunOnce(ctx)
				} else {
					err = loop.Run(ctx)
				}
				if err != nil {
					t.Fatal(err)
				}
				lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
				if len(lines) != 2 {
					t.Fatal("watch did not complete exactly one reported tick")
				}
				event := decodeWatchEvent(t, append(slices.Clone(lines[1]), '\n'))
				matched := mode == "same tip" || mode == "same older header"
				if matched {
					if event.Event != "caught_up" || saves != 1 || event.Error != nil || once && result.Outcome != verify.OutcomeAccept {
						t.Fatal("matching retained target did not complete a caught-up tick")
					}
				} else {
					if event.Event != "refused" || saves != 0 || event.Persistence != "not_attempted" || once && result.Outcome != verify.OutcomeRefused {
						t.Fatalf("unbound target reported caught up or saved trusted state: event=%s saves=%d", event.Event, saves)
					}
					wantReason, wantCategory := "ReasonRetainedHeaderMismatch", "header_mismatch"
					if mode == "evicted height" {
						wantReason, wantCategory = "ReasonHeightOutOfWindow", "height_unavailable"
					}
					if event.Reason == nil || *event.Reason != wantReason || event.Error == nil ||
						event.Error.Stage != "retained_target" || event.Error.Category != wantCategory {
						t.Fatal("retained-target refusal lost its fixed reason or error category")
					}
					unchanged()
				}
				if event.Verification != nil || event.CandidateTip != nil || event.FetchedCount != 0 || event.StateTip.Height != 1006 {
					t.Fatal("retained-target comparison claimed a new header verification or state advance")
				}
				checkWatchOutputLockReleased(t, loop.StatePath)
			})
		}
	}
}
