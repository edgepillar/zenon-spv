package verify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func delayedSegmentFixture(t *testing.T) (GenesisTrustRoot, []chain.Header, proof.AccountSegment, []proof.CommitmentEvidence) {
	t.Helper()
	base, segment, _, _ := segmentFixture(t)
	previous := base.Genesis
	var headers []chain.Header
	var evidence []proof.CommitmentEvidence
	for height := uint64(101); height <= 114; height++ {
		var flat []chain.AccountHeader
		for i, confirming := range []uint64{104, 107} {
			if height == confirming {
				flat = []chain.AccountHeader{segment.Blocks[i].AccountHeader()}
				evidence = append(evidence, proof.CommitmentEvidence{Height: height, Target: flat[0], Flat: &proof.FlatContentEvidence{SortedHeaders: flat}})
			}
		}
		h := boundaryHeader(previous, height, chain.MomentumContentHash(flat))
		headers = append(headers, h)
		previous.Height, previous.HeaderHash = height, h.HeaderHash
	}
	return base.Genesis, headers, segment, evidence
}

func TestRetentionSeparatesHistoryFromDepth(t *testing.T) {
	anchor, headers, segment, evidence := delayedSegmentFixture(t)
	opts := VerifyOptions{Policy: DefaultPolicy()}
	opts.Policy.W, opts.Policy.RetainHeaders = 2, 10
	state, err := NewVerifiedState(anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	result, state := state.Extend(headers[:10])
	if result.Outcome != OutcomeAccept {
		t.Fatal(result)
	}
	summary, _ := state.RetainedSummary()
	if summary.Count != 10 || summary.Capacity != 10 || *summary.DepthEligible != (RetainedDepthRange{101, 108}) {
		t.Fatal(summary)
	}
	for _, row := range state.VerifySegment(segment, evidence).Blocks {
		if row.Outcome != OutcomeAccept {
			t.Fatal("separate confirming momentums failed", row)
		}
	}
	shallow := evidence[1]
	shallow.Height = 110
	if r := state.VerifyCommitment(shallow); r.Reason != ReasonInsufficientFinality || r.Outcome != OutcomeRefused {
		t.Fatal(r)
	}
	before := state.Snapshot()
	bad := cloneStateHeader(headers[10])
	bad.Signature[0] ^= 1
	if r, after := state.Extend([]chain.Header{bad}); r.Outcome != OutcomeReject || !reflect.DeepEqual(before, after.Snapshot()) {
		t.Fatal("failed extension changed retained history")
	}
	result, state = state.Extend(headers[10:13])
	if result.Outcome != OutcomeAccept || state.VerifyCommitment(evidence[0]).Outcome != OutcomeAccept {
		t.Fatal("delayed proof was evicted before K was exhausted")
	}
	result, state = state.Extend(headers[13:])
	if result.Outcome != OutcomeAccept || state.VerifyCommitment(evidence[0]).Reason != ReasonHeightOutOfWindow || state.VerifyCommitment(evidence[1]).Outcome != OutcomeAccept {
		t.Fatal("wrong eviction/depth boundary")
	}
}

func TestRetentionPersistenceMigrationAndAuthorizationBeforeShrink(t *testing.T) {
	for _, profile := range []bool{false, true} {
		anchor, headers, _, evidence := delayedSegmentFixture(t)
		opts := VerifyOptions{Policy: DefaultPolicy()}
		opts.Policy.W, opts.Policy.RetainHeaders = 2, 10
		if profile {
			opts.Policy.ProtocolProfile = &ProtocolProfile{Version: 1, Anchor: anchor, ValidThrough: 200, Source: "synthetic"}
		}
		state, err := NewVerifiedState(anchor, opts)
		if err != nil {
			t.Fatal(err)
		}
		_, state = state.Extend(headers[:10])
		path := filepath.Join(t.TempDir(), "state.json")
		if err := state.Save(path); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(path)
		var wire persistedState
		if json.Unmarshal(raw, &wire) != nil || wire.Version != 3 || wire.Capacity != 10 {
			t.Fatal("explicit retention did not use schema 3")
		}
		loaded, err := LoadTrustedState(path, anchor, opts)
		if err != nil || loaded.VerifyCommitment(evidence[0]).Outcome != OutcomeAccept {
			t.Fatal("delayed proof lost on resume", err)
		}
		context, _ := loaded.VerificationContext()
		if context.SchemaVersion != 2 || context.Policy.RetainHeaders != 10 {
			t.Fatal(context)
		}
		legacy := opts
		legacy.Policy.RetainHeaders = 0
		if _, err := LoadTrustedState(path, anchor, legacy); err == nil {
			t.Fatal("omitted retention silently shrank schema 3 state")
		}
		shrink := opts
		shrink.Policy.RetainHeaders = 8
		var entries []ProducerEntry
		for _, h := range headers[2:10] {
			entries = append(entries, ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
		}
		schedule, err := NewProducerSchedule(anchor.ChainID, []ProducerCoverage{{103, 110}}, entries, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		shrink.ProducerAuth = ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: NewScheduleAuthorizer(schedule)}
		_, err = LoadTrustedState(path, anchor, shrink)
		var auth *StateAuthorizationError
		if !errors.As(err, &auth) || auth.Result.Reason != ReasonProducerSetUnknown {
			t.Fatal("eviction bypassed full saved-window authorization", err)
		}
		after, _ := os.ReadFile(path)
		if string(after) != string(raw) {
			t.Fatal("load modified saved state")
		}
		shrink.ProducerAuth = ProducerAuthOptions{}
		resized, err := LoadTrustedState(path, anchor, shrink)
		if err != nil || resized.Snapshot().Capacity != 8 || cap(resized.data.state.RetainedWindow) != 8 || resized.RequireContextFingerprint(*context.Fingerprint) == nil {
			t.Fatal("explicit resize did not change the context", err)
		}
		// A schema 1/2 file can opt in, but evicted history never reappears.
		old, err := NewVerifiedState(anchor, legacy)
		if err != nil {
			t.Fatal(err)
		}
		_, old = old.Extend(headers[:10])
		if err := old.Save(path); err != nil {
			t.Fatal(err)
		}
		migrated, err := LoadTrustedState(path, anchor, opts)
		if err != nil || len(migrated.Snapshot().RetainedWindow) != 3 || migrated.VerifyCommitment(evidence[0]).Reason != ReasonHeightOutOfWindow {
			t.Fatal("migration invented missing history", err)
		}
		if err := migrated.Save(path); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTrustedState(path, anchor, legacy); err == nil {
			t.Fatal("migration did not persist explicit retention")
		}
	}
}

func TestRetentionBoundsFailBeforeAllocation(t *testing.T) {
	anchor := GenesisTrustRoot{ChainID: 3, Height: 100, HeaderHash: chain.Hash{1}}
	for _, p := range []Policy{{W: 6, RetainHeaders: -1}, {W: 6, RetainHeaders: 6}, {W: 6, RetainHeaders: MaxRetainHeaders + 1}, {W: ^uint64(0)}} {
		if _, err := NewVerifiedState(anchor, VerifyOptions{Policy: p}); !errors.Is(err, ErrInvalidRetentionPolicy) {
			t.Fatal("invalid retention accepted", err)
		}
		if s := NewHeaderState(anchor, p); s.Capacity != 0 || cap(s.RetainedWindow) != 0 {
			t.Fatal("invalid low-level policy allocated history")
		}
	}
	for _, k := range []int{7, MaxRetainHeaders} {
		p := DefaultPolicy()
		p.RetainHeaders = k
		if _, err := NewVerifiedState(anchor, VerifyOptions{Policy: p}); err != nil {
			t.Fatal(err)
		}
	}
	// Raw callers cannot force the working copy past its declared capacity.
	p := DefaultPolicy()
	p.RetainHeaders = 7
	malformed := NewHeaderState(anchor, p)
	malformed.RetainedWindow = make([]chain.Header, 8)
	before := cloneHeaderState(malformed)
	r, after := VerifyHeaders([]chain.Header{{Height: 101}}, malformed, p)
	if r.Outcome != OutcomeRefused || r.Reason != ReasonInvalidRetentionPolicy || !reflect.DeepEqual(before, after) {
		t.Fatal("oversized retained window was copied or changed")
	}
}
