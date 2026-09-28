package syncer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestRun_PersistenceAdapterCannotChangeVerifiedState(t *testing.T) {
	loop, out, _ := persistenceLoop(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var tips []uint64
	loop.SaveState = func(path string, snapshot verify.HeaderState) error {
		tip, _ := snapshot.Tip()
		tips = append(tips, tip.Height)
		if err := verify.SaveHeaderState(path, snapshot); err != nil {
			return err
		}
		// An adapter may retain or reuse its argument after saving. Neither
		// mutations to the header array nor its byte slices may reach the loop.
		snapshot.RetainedWindow[0].Signature[0] ^= 1
		snapshot.RetainedWindow[len(snapshot.RetainedWindow)-1].HeaderHash[0] ^= 1
		if len(tips) == 2 {
			cancel()
		}
		return nil
	}
	if err := loop.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(tips) != 2 || tips[0] != 1009 || tips[1] != 1012 {
		t.Fatalf("adapter mutation prevented verified progress: tips=%v logs=%s", tips, out.String())
	}
	loaded, err := verify.LoadHeaderState(loop.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if tip, _ := loaded.Tip(); tip.Height != 1012 {
		t.Fatalf("unexpected persisted tip: %d", tip.Height)
	}
	for _, tag := range []verify.TrustAssumption{verify.TrustConfiguredAnchor, verify.TrustPersistedState} {
		if !strings.Contains(out.String(), string(tag)) {
			t.Errorf("watch startup omitted %s", tag)
		}
	}
}

func TestTick_ZeroStateRefusesBeforeNetworkUse(t *testing.T) {
	loop := &Loop{}
	r, state := loop.tick(context.Background(), verify.VerifiedState{})
	if r.Outcome != verify.OutcomeRefused || r.Reason != verify.ReasonMissingEvidence || !state.Empty() {
		t.Fatalf("zero state produced watch progress: %+v", r)
	}
}
