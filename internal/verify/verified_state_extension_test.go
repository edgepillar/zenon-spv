package verify

import (
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

// These signed synthetic fixtures exercise ownership, not canonicality,
// finality, activation, or execution of the repeated account header.
func extensionOwnershipFixture(t *testing.T, count int) (GenesisTrustRoot, []chain.Header, VerifyOptions, proof.CommitmentEvidence) {
	t.Helper()
	anchor, headers, key := buildChain(t, count)
	member := chain.AccountHeader{Address: chain.Address{1}, Height: 1, Hash: chain.Hash{2}}
	flat := []chain.AccountHeader{member}
	content := chain.MomentumContentHash(flat)
	previous := anchor.HeaderHash
	for i := range headers {
		headers[i].PreviousHash = previous
		headers[i].ContentHash = content
		headers[i].HeaderHash = headers[i].ComputeHash()
		headers[i].Signature = ed25519.Sign(key, headers[i].HeaderHash[:])
		previous = headers[i].HeaderHash
	}
	opts := VerifyOptions{Policy: DefaultPolicy(), ProducerAuth: ProducerAuthOptions{
		Mode: ProducerAuthRequired, Authorizer: NewScheduleAuthorizer(fixtureSchedule(t, count))}}
	opts.Policy.W, opts.Policy.RetainHeaders = 1, 4
	opts.Policy.ProtocolProfile = &ProtocolProfile{Version: 1, Anchor: anchor,
		ValidThrough: headers[len(headers)-1].Height, Source: "synthetic extension ownership fixture"}
	evidence := proof.CommitmentEvidence{Height: headers[0].Height, Target: member,
		Flat: &proof.FlatContentEvidence{SortedHeaders: flat}}
	return anchor, headers, opts, evidence
}

func copyExtensionHeaders(headers []chain.Header) []chain.Header {
	out := make([]chain.Header, len(headers))
	for i, h := range headers {
		out[i] = cloneStateHeader(h)
	}
	return out
}

func expectedExtensionWindow(initial HeaderState, headers []chain.Header, count int) HeaderState {
	initial.ProtocolProfile = cloneProtocolProfile(initial.ProtocolProfile)
	first := max(0, count-initial.Capacity)
	initial.RetainedWindow = copyExtensionHeaders(headers[first:count])
	return initial
}

func mutateExtensionInputs(headers []chain.Header) {
	for i := range headers {
		headers[i].PublicKey[0] ^= 1
		headers[i].Signature[0] ^= 1
		headers[i].Height = 0
		headers[i].HeaderHash = chain.Hash{}
		headers[i].ContentHash = chain.Hash{}
	}
}

// Inspect and mutate every public view, then check the complete expected
// bytes/settings again. This also checks that a diagnostic cannot lower W.
func inspectExtensionHandle(state VerifiedState, want HeaderState, context VerificationContext) error {
	if !reflect.DeepEqual(state.Snapshot(), want) {
		return fmt.Errorf("signed retained bytes or window changed")
	}
	gotContext, err := state.VerificationContext()
	if err != nil || !reflect.DeepEqual(gotContext, context) {
		return fmt.Errorf("captured context changed: %v", err)
	}
	tip, ok := state.Tip()
	if ok != (len(want.RetainedWindow) > 0) {
		return fmt.Errorf("tip availability changed")
	}
	if ok {
		if !reflect.DeepEqual(tip, want.RetainedWindow[len(want.RetainedWindow)-1]) {
			return fmt.Errorf("tip bytes changed")
		}
		tip.PublicKey[0] ^= 1
		tip.Signature[0] ^= 1
		tip.Height = 0
	}
	for _, h := range want.RetainedWindow {
		view, ok := state.HeaderAtHeight(h.Height)
		if !ok || !reflect.DeepEqual(view, h) {
			return fmt.Errorf("retained lookup bytes changed at height %d", h.Height)
		}
		view.PublicKey[0] ^= 1
		view.Signature[0] ^= 1
		view.PreviousHash = chain.Hash{}
	}
	for _, height := range []uint64{0, want.Genesis.Height, ^uint64(0)} {
		if _, ok := state.HeaderAtHeight(height); ok {
			return fmt.Errorf("lookup returned an unavailable height")
		}
	}
	view := state.Snapshot()
	view.Genesis.HeaderHash = chain.Hash{}
	view.ProtocolProfile.ValidThrough = 0
	view.ProtocolProfile.Source = "changed view"
	for i := range view.RetainedWindow {
		view.RetainedWindow[i].PublicKey[0] ^= 1
		view.RetainedWindow[i].Signature[0] ^= 1
		view.RetainedWindow[i].HeaderHash = chain.Hash{}
	}
	gotContext.Policy.W = 0
	gotContext.ProtocolProfile.ValidThrough = 0
	*gotContext.Fingerprint = chain.Hash{}
	*gotContext.Producer.ScheduleHash = chain.Hash{}
	if !reflect.DeepEqual(state.Snapshot(), want) {
		return fmt.Errorf("a public view exposed retained-state memory")
	}
	afterContext, err := state.VerificationContext()
	if err != nil || !reflect.DeepEqual(afterContext, context) {
		return fmt.Errorf("a diagnostic exposed captured settings: %v", err)
	}
	if err := state.RequireContextFingerprint(*context.Fingerprint); err != nil {
		return fmt.Errorf("captured context pin changed: %v", err)
	}
	return nil
}

func inspectExtensionInclusion(state VerifiedState, want HeaderState, context VerificationContext, evidence proof.CommitmentEvidence, persisted bool) error {
	if len(want.RetainedWindow) == 0 {
		if r := state.VerifyCommitment(evidence); r.Outcome != OutcomeRefused || r.Reason != ReasonHeightOutOfWindow {
			return fmt.Errorf("empty state supplied inclusion: %s", r)
		}
		return nil
	}
	evidence.Height = want.RetainedWindow[0].Height
	r := state.VerifyCommitment(evidence)
	if uint64(len(want.RetainedWindow)-1) < context.Policy.W {
		if r.Outcome != OutcomeRefused || r.Reason != ReasonInsufficientFinality {
			return fmt.Errorf("query lowered captured depth: %s", r)
		}
	} else if r.Outcome != OutcomeAccept || !slices.Contains(r.Proven, GuaranteeContentInclusion) ||
		!slices.Contains(r.NotProven, GuaranteeCanonicality) ||
		!slices.Contains(r.TrustAssumptions, TrustConfiguredAnchor) ||
		!slices.Contains(r.TrustAssumptions, TrustExternalProtocolProfile) ||
		!slices.Contains(r.TrustAssumptions, TrustExternalProducerSchedule) ||
		slices.Contains(r.TrustAssumptions, TrustPersistedState) != persisted {
		return fmt.Errorf("retained inclusion or trust boundary changed: %s", r)
	}
	evidence.Height = want.RetainedWindow[len(want.RetainedWindow)-1].Height
	if r := state.VerifyCommitment(evidence); r.Outcome != OutcomeRefused || r.Reason != ReasonInsufficientFinality {
		return fmt.Errorf("tip query bypassed captured depth: %s", r)
	}
	return nil
}

func TestVerifiedState_ExtensionOwnershipMatrix(t *testing.T) {
	for _, populated := range []int{0, 2, 4} {
		for _, batch := range []int{1, 3, 4, 5} {
			t.Run(fmt.Sprintf("populated%d/batch%d", populated, batch), func(t *testing.T) {
				end := populated + batch
				anchor, headers, opts, evidence := extensionOwnershipFixture(t, end+2)
				original := copyExtensionHeaders(headers)
				resumeOpts := opts
				resumeOpts.Policy.ProtocolProfile = cloneProtocolProfile(opts.Policy.ProtocolProfile)
				resumeOpts.ProducerAuth.Authorizer = NewScheduleAuthorizer(fixtureSchedule(t, len(headers)))
				base, err := NewVerifiedState(anchor, opts)
				if err != nil {
					t.Fatal(err)
				}
				initial := base.Snapshot()
				context, err := base.VerificationContext()
				if err != nil {
					t.Fatal(err)
				}
				// Caller-owned policy/schedule changes must not weaken later extension.
				opts.Policy.W = 0
				opts.Policy.ProtocolProfile.ValidThrough = 0
				opts.ProducerAuth.Authorizer.(*ScheduleAuthorizer).Schedule.Entries[0].ProducingAddr = chain.Address{}
				if populated > 0 {
					r, next := base.Extend(headers[:populated])
					if r.Outcome != OutcomeAccept {
						t.Fatal("fixture population failed", r)
					}
					base = next
				}
				r, child := base.Extend(headers[populated:end])
				if r.Outcome != OutcomeAccept {
					t.Fatal("extension failed", r)
				}
				r, sibling := base.Extend(copyExtensionHeaders(original[populated:end]))
				if r.Outcome != OutcomeAccept {
					t.Fatal("sibling extension failed", r)
				}
				r, grandchild := child.Extend(copyExtensionHeaders(original[end:]))
				if r.Outcome != OutcomeAccept {
					t.Fatal("grandchild extension failed", r)
				}
				mutateExtensionInputs(headers[:end])
				for _, handle := range []struct {
					state VerifiedState
					count int
				}{
					{base, populated}, {child, end}, {sibling, end}, {grandchild, end + 2},
				} {
					want := expectedExtensionWindow(initial, original, handle.count)
					if err := inspectExtensionHandle(handle.state, want, context); err != nil {
						t.Fatal(err)
					}
					if err := inspectExtensionInclusion(handle.state, want, context, evidence, false); err != nil {
						t.Fatal(err)
					}
				}
				for i, handle := range []struct {
					state VerifiedState
					count int
				}{{child, end}, {grandchild, end + 2}} {
					path := filepath.Join(t.TempDir(), fmt.Sprintf("state-%d.json", i))
					if err := handle.state.Save(path); err != nil {
						t.Fatal("mutations corrupted saved signed envelopes", err)
					}
					loaded, err := LoadTrustedState(path, anchor, resumeOpts)
					if err != nil {
						t.Fatal("trusted resume failed", err)
					}
					want := expectedExtensionWindow(initial, original, handle.count)
					if err := inspectExtensionHandle(loaded, want, context); err != nil {
						t.Fatal(err)
					}
					if err := inspectExtensionInclusion(loaded, want, context, evidence, true); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestVerifiedState_ExtensionFailureAfterValidPrefix(t *testing.T) {
	for _, tc := range []struct {
		name      string
		populated int
		outcome   Outcome
		reason    ReasonCode
		failedAt  int
	}{
		{"signature", 4, OutcomeReject, ReasonInvalidSignature, 1},
		{"profile", 4, OutcomeRefused, ReasonProtocolProfileCoverage, 1},
		{"schedule", 4, OutcomeRefused, ReasonProducerSetUnknown, -1},
		{"window", 0, OutcomeRefused, ReasonWindowNotMet, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			anchor, headers, opts, _ := extensionOwnershipFixture(t, tc.populated+2)
			switch tc.name {
			case "signature":
				headers[tc.populated+1].Signature[0] ^= 1
			case "profile":
				opts.Policy.ProtocolProfile.ValidThrough = headers[tc.populated].Height
			case "schedule":
				opts.ProducerAuth.Authorizer = NewScheduleAuthorizer(fixtureSchedule(t, tc.populated+1))
			case "window":
				opts.Policy.W = 3
			}
			base, err := NewVerifiedState(anchor, opts)
			if err != nil {
				t.Fatal(err)
			}
			if tc.populated > 0 {
				r, next := base.Extend(headers[:tc.populated])
				if r.Outcome != OutcomeAccept {
					t.Fatal("fixture population failed", r)
				}
				base = next
			}
			want := base.Snapshot()
			context, err := base.VerificationContext()
			if err != nil {
				t.Fatal(err)
			}
			r, failed := base.Extend(headers[tc.populated:])
			if r.Outcome != tc.outcome || r.Reason != tc.reason || r.FailedAt != tc.failedAt || len(r.Proven) != 0 {
				t.Fatal("valid prefix changed failure semantics", r)
			}
			mutateExtensionInputs(headers)
			for _, handle := range []VerifiedState{base, failed} {
				if err := inspectExtensionHandle(handle, want, context); err != nil {
					t.Fatal("failed extension changed its predecessor", err)
				}
			}
		})
	}
}

func TestVerifiedState_ConcurrentSiblingExtensionsAndViews(t *testing.T) {
	anchor, headers, opts, evidence := extensionOwnershipFixture(t, 7)
	base, err := NewVerifiedState(anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	initial := base.Snapshot()
	r, base := base.Extend(headers[:4])
	if r.Outcome != OutcomeAccept {
		t.Fatal(r)
	}
	context, err := base.VerificationContext()
	if err != nil {
		t.Fatal(err)
	}
	wantBase := expectedExtensionWindow(initial, headers, 4)
	wantChild := expectedExtensionWindow(initial, headers, 6)
	wantGrandchild := expectedExtensionWindow(initial, headers, 7)
	failures := make(chan error, 6)
	var wg sync.WaitGroup
	for worker := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 8 {
				if err := inspectExtensionHandle(base, wantBase, context); err != nil {
					failures <- err
					return
				}
				if err := inspectExtensionInclusion(base, wantBase, context, evidence, false); err != nil {
					failures <- err
					return
				}
				if worker >= 4 {
					continue
				}
				incoming := copyExtensionHeaders(headers[4:6])
				r, child := base.Extend(incoming)
				if r.Outcome != OutcomeAccept {
					failures <- fmt.Errorf("concurrent sibling failed: %s", r)
					return
				}
				mutateExtensionInputs(incoming)
				if err := inspectExtensionHandle(child, wantChild, context); err != nil {
					failures <- err
					return
				}
				r, grandchild := child.Extend(copyExtensionHeaders(headers[6:]))
				if r.Outcome != OutcomeAccept {
					failures <- fmt.Errorf("concurrent descendant failed: %s", r)
					return
				}
				if err := inspectExtensionHandle(grandchild, wantGrandchild, context); err != nil {
					failures <- err
					return
				}
				if err := inspectExtensionInclusion(grandchild, wantGrandchild, context, evidence, false); err != nil {
					failures <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if err := inspectExtensionHandle(base, wantBase, context); err != nil {
		t.Fatal("concurrent extension changed the predecessor", err)
	}
}
