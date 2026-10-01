package syncer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestWatchBindsCompletedBatchToSelectedTarget(t *testing.T) {
	for _, mode := range []string{"same target", "changed hash", "changed signer", "changed signature", "single header changed", "partial batch", "matching invalid signature"} {
		t.Run(mode, func(t *testing.T) {
			loop, output, _ := persistenceLoop(t)
			loop.JSON, loop.Interval = true, time.Hour
			_, headers, preimages := chainFixtureRPC(t, 10)
			targetIndex := 8
			if mode == "single header changed" {
				targetIndex = 6
				loop.SafetyMargin = 3
			}
			if mode == "partial batch" {
				loop.BatchSize = 2
			}
			if mode == "matching invalid signature" {
				headers[targetIndex].Signature[0] ^= 1
			}
			selected := headers[targetIndex]
			switch mode {
			case "changed hash", "single header changed", "partial batch":
				selected.TimestampUnix++
				selected.HeaderHash = selected.ComputeHash()
				selected.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), selected.HeaderHash[:])
			case "changed signer":
				seed := make([]byte, ed25519.SeedSize)
				seed[0] = 1
				key := ed25519.NewKeyFromSeed(seed)
				selected.PublicKey = key.Public().(ed25519.PublicKey)
				selected.Signature = ed25519.Sign(key, selected.HeaderHash[:])
			case "changed signature":
				selected.Signature = slices.Clone(selected.Signature)
				selected.Signature[0] ^= 1
			}
			first := startChangingTargetPeer(t, headers, preimages, selected)
			second := startChangingTargetPeer(t, headers, preimages, selected)
			loop.Multi = fetch.NewMultiClient([]string{first, second})
			unchanged := protectWatchOutputState(t, loop.StatePath)
			saves := 0
			loop.SaveState = func(path string, state verify.HeaderState) error {
				saves++
				return verify.SaveHeaderState(path, state)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := loop.RunOnce(ctx)
			if err != nil {
				t.Fatal(err)
			}
			lines := bytes.Split(bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), []byte{'\n'})
			if len(lines) != 2 {
				t.Fatal("watch did not emit one completed tick")
			}
			event := decodeWatchEvent(t, append(slices.Clone(lines[1]), '\n'))
			switch mode {
			case "same target", "partial batch":
				wantTip := uint64(1009)
				if mode == "partial batch" {
					wantTip = 1008
				}
				if result.Outcome != verify.OutcomeAccept || saves != 1 || event.StateTip.Height != wantTip || event.Event != "advanced" {
					t.Fatal("target binding rejected a matching or incomplete batch")
				}
			case "matching invalid signature":
				if result.Outcome != verify.OutcomeReject || result.Reason != verify.ReasonInvalidSignature || saves != 0 {
					t.Fatal("target agreement bypassed cryptographic verification")
				}
				unchanged()
			default:
				if result.Outcome != verify.OutcomeRefused || saves != 0 || event.Event != "refused" || event.Persistence != "not_attempted" {
					t.Fatalf("changed target was accepted or saved: outcome=%s saves=%d", result.Outcome, saves)
				}
				if event.Verification != nil || event.CandidateTip != nil || event.StateTip.Height != 1006 {
					t.Fatal("conflicting RPC snapshots claimed verified progress")
				}
				if result.Reason != verify.ReasonTargetHeaderMismatch || event.Reason == nil || *event.Reason != "ReasonTargetHeaderMismatch" ||
					event.Error == nil || event.Error.Stage != "target_binding" || event.Error.Category != "header_mismatch" ||
					event.FetchedCount != len(result.FetchedHeights) || event.FetchedCount == 0 {
					t.Fatal("changed target lost its fetched count or fixed refusal diagnostics")
				}
				unchanged()
			}
			checkWatchOutputLockReleased(t, loop.StatePath)
		})
	}
}

// Both RPC rounds have unanimous peer agreement. Only the selected target and
// the later range disagree, including when both requests use the same height.
func startChangingTargetPeer(t *testing.T, headers []chain.Header, preimages [][]byte, selected chain.Header) string {
	t.Helper()
	var targetReads atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage
			Method string
			Params []uint64
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		var result any
		switch req.Method {
		case "ledger.getFrontierMomentum":
			result = rpcMomentumOf(headers[len(headers)-1], preimages[len(headers)-1], true)
		case "ledger.getMomentumsByHeight":
			if len(req.Params) != 2 {
				t.Error("unexpected watch range parameters")
				return
			}
			start, count := req.Params[0], req.Params[1]
			list := make([]any, 0, count)
			for i := range count {
				idx := indexOfHeight(headers, start+i)
				if idx < 0 {
					t.Error("unexpected watch range height")
					return
				}
				header := headers[idx]
				if start == selected.Height && count == 1 && targetReads.Add(1) == 1 {
					header = selected
				}
				list = append(list, rpcMomentumOf(header, preimages[idx], true))
			}
			result = map[string]any{"list": list}
		default:
			t.Error("unexpected watch RPC method")
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}
