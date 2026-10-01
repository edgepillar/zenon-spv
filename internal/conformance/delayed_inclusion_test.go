package conformance_test

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func delayedInclusionBundle(t *testing.T) (accountSegmentCorpus, proof.HeaderBundle) {
	t.Helper()
	c := loadNodeAccountCorpus(t, "delayed-inclusion.json")
	if c.Chain.Anchor.Height != 5000 || c.Chain.V2FromHeight != 5009 || len(c.Segments) != 2 {
		t.Fatal("unexpected delayed-inclusion corpus")
	}
	for _, segment := range c.Segments {
		if len(segment.Vectors) != 3 {
			t.Fatal("incomplete delayed account segment")
		}
	}
	bundle := accountBundleFromCorpus(t, c)
	heights := map[uint64]int{}
	for _, evidence := range bundle.Commitments {
		heights[evidence.Height]++
	}
	if !reflect.DeepEqual(heights, map[uint64]int{5003: 2, 5007: 2, 5011: 2}) {
		t.Fatal("node corpus lost separate confirming momentums")
	}
	return c, bundle
}

func delayedOptions(t testing.TB, c accountSegmentCorpus) (verify.VerifyOptions, *verify.ProducerSchedule) {
	t.Helper()
	policy := verify.DefaultPolicy()
	policy.RetainHeaders = 16
	policy.ProtocolProfile = &verify.ProtocolProfile{Version: 1, Anchor: c.Chain.Anchor,
		V2FromHeight: 5009, ValidThrough: 5019, Source: "synthetic delayed inclusion profile"}
	var entries []verify.ProducerEntry
	for _, v := range c.Chain.Vectors {
		h := v.Header
		entries = append(entries, verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix,
			ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
	}
	schedule, err := verify.NewProducerSchedule(c.Chain.Anchor.ChainID,
		[]verify.ProducerCoverage{{FromHeight: 5001, ThroughHeight: 5019}}, entries, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return verify.VerifyOptions{Policy: policy,
		ProducerAuth: verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired, Authorizer: verify.NewScheduleAuthorizer(schedule)}}, schedule
}

func assertDelayedSegments(t testing.TB, state verify.VerifiedState, bundle proof.HeaderBundle) {
	t.Helper()
	for _, segment := range bundle.Segments {
		result := state.VerifySegment(segment, bundle.Commitments)
		if len(result.Blocks) != len(segment.Blocks) {
			t.Fatal("lost delayed account targets")
		}
		for _, row := range result.Blocks {
			if row.Outcome != verify.OutcomeAccept || !slices.Contains(row.Proven, verify.GuaranteeContentInclusion) ||
				slices.Contains(row.Proven, verify.GuaranteeSignatureAuthenticity) == segment.Address.IsEmbeddedAddress() ||
				!slices.Contains(row.TrustAssumptions, verify.TrustExternalProducerSchedule) ||
				slices.Contains(row.Proven, verify.GuaranteeCanonicality) || slices.Contains(row.Proven, verify.GuaranteeStateTransition) {
				t.Fatal("delayed inclusion changed the bounded guarantee contract", row)
			}
		}
	}
}

func TestNodeDelayedInclusionAcrossVersionsAndResume(t *testing.T) {
	c, bundle := delayedInclusionBundle(t)
	opts, _ := delayedOptions(t, c)
	state, err := verify.NewVerifiedState(c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	r, state := state.Extend(bundle.Headers[:16])
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	for _, segment := range bundle.Segments {
		rows := state.VerifySegment(segment, bundle.Commitments).Blocks
		if len(rows) != 3 || rows[0].Outcome != verify.OutcomeAccept || rows[1].Outcome != verify.OutcomeAccept ||
			rows[2].Outcome != verify.OutcomeRefused || rows[2].Reason != verify.ReasonInsufficientFinality {
			t.Fatal("separate confirming heights lost their independent depth checks", rows)
		}
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	state, err = verify.LoadTrustedState(path, c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	context, err := state.VerificationContext()
	if err != nil || context.SchemaVersion != 2 || context.Fingerprint == nil {
		t.Fatal("missing explicit-retention context", err)
	}
	r, state = state.Extend(bundle.Headers[16:17])
	if r.Outcome != verify.OutcomeAccept || state.RequireContextFingerprint(*context.Fingerprint) != nil {
		t.Fatal("resume changed policy or failed to reach exact depth", r)
	}
	assertDelayedSegments(t, state, bundle)
	before := state.Snapshot()
	bad := bundle.Headers[17]
	bad.NextFusionPrice++
	if result, next := state.Extend([]chain.Header{bad}); result.Outcome != verify.OutcomeReject || !reflect.DeepEqual(before, next.Snapshot()) {
		t.Fatal("tampered v2 extension changed delayed history")
	}
	wrongHeight := bundle.Commitments[0]
	wrongHeight.Height = 5007
	if result := state.VerifyCommitment(wrongHeight); result.Outcome != verify.OutcomeReject || result.Reason != verify.ReasonInvalidContent {
		t.Fatal("a valid proof moved to a different confirming momentum", result)
	}
	r, state = state.Extend(bundle.Headers[17:18])
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	assertDelayedSegments(t, state, bundle)
	summary, err := state.RetainedSummary()
	if err != nil || summary.Count != 16 || summary.Oldest.Height != 5003 || summary.DepthEligible == nil ||
		*summary.DepthEligible != (verify.RetainedDepthRange{FromHeight: 5003, ThroughHeight: 5012}) {
		t.Fatal("wrong delayed-query availability", summary, err)
	}
	r, state = state.Extend(bundle.Headers[18:])
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	for _, segment := range bundle.Segments {
		rows := state.VerifySegment(segment, bundle.Commitments).Blocks
		if rows[0].Reason != verify.ReasonHeightOutOfWindow || rows[0].Outcome != verify.OutcomeRefused ||
			rows[1].Reason != verify.ReasonParentNotAccepted || rows[2].Reason != verify.ReasonParentNotAccepted {
			t.Fatal("eviction was confused with invalidity or allowed an unaccepted parent", rows)
		}
	}
	partial := bundle
	partial.Segments = slices.Clone(bundle.Segments)
	for i := range partial.Segments {
		partial.Segments[i].Blocks = partial.Segments[i].Blocks[1:]
	}
	assertDelayedSegments(t, state, partial)
	// Larger history was necessary: a legacy window at the same tip has lost
	// every target even though each has sufficient subsequent-header depth.
	opts.Policy.RetainHeaders = 0
	legacy, err := verify.NewVerifiedState(c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	r, legacy = legacy.Extend(bundle.Headers)
	if r.Outcome != verify.OutcomeAccept || legacy.VerifyCommitment(bundle.Commitments[5]).Reason != verify.ReasonHeightOutOfWindow {
		t.Fatal("legacy comparison did not exercise discarded history")
	}
}
