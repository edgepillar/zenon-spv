// SPDX-License-Identifier: MIT

package verify

import (
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"sync"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestExperimentalV3OwnedHeaderRootFlow(t *testing.T) {
	f := experimentalV3Inputs(t)
	empty := experimentalV3New(t, f)
	if !empty.Empty() {
		t.Fatal("constructor supplied evidence")
	}
	if _, err := empty.RootAt(12, f.headers[0].Header.HeaderHash, f.pin); err != ErrExperimentalV3HeaderUnavailable {
		t.Fatal("empty state supplied a root", err)
	}
	r, one := empty.Extend(f.headers[:1])
	if r.Outcome != OutcomeAccept || one.Empty() || !empty.Empty() {
		t.Fatal("first owned extension", r)
	}
	if _, err := one.RootAt(12, f.headers[0].Header.HeaderHash, f.pin); err != ErrExperimentalV3Depth {
		t.Fatal("tip depth treated as finality", err)
	}
	r, two := one.Extend(f.headers[1:2])
	if r.Outcome != OutcomeAccept {
		t.Fatal(r)
	}
	root, err := two.RootAt(12, f.headers[0].Header.HeaderHash, f.pin)
	if err != nil || root != f.headers[0].StateRoot {
		t.Fatal("root was not selected from the owned header", err)
	}
	for _, g := range []Guarantee{GuaranteeHeaderChainIntegrity, GuaranteeSignatureAuthenticity, GuaranteeProducerAuthorization} {
		if !containsGuarantee(r.Proven, g) {
			t.Fatal("missing precise header guarantee", g)
		}
	}
	for _, g := range []Guarantee{GuaranteeCanonicality, GuaranteeStateTransition, GuaranteeStateValueInclusion, GuaranteeContentInclusion} {
		if containsGuarantee(r.Proven, g) || !containsGuarantee(r.NotProven, g) {
			t.Fatal("unsupported claim", g)
		}
	}
	for _, trust := range []TrustAssumption{TrustConfiguredAnchor, TrustExternalProtocolProfile, TrustExternalProducerSchedule} {
		found := false
		for _, got := range r.TrustAssumptions {
			if got == trust {
				found = true
			}
		}
		if !found {
			t.Fatal("hidden trust input", trust)
		}
	}
	r, three := two.Extend(f.headers[2:])
	if r.Outcome != OutcomeAccept {
		t.Fatal(r)
	}
	if _, err := three.RootAt(12, f.headers[0].Header.HeaderHash, f.pin); err != ErrExperimentalV3HeaderUnavailable {
		t.Fatal("evicted root remained available", err)
	}
	if got, err := three.RootAt(13, f.headers[1].Header.HeaderHash, f.pin); err != nil || got != f.headers[1].StateRoot {
		t.Fatal("retained depth after eviction", err)
	}
	if _, err := two.RootAt(12, f.headers[0].Header.HeaderHash, f.pin); err != nil {
		t.Fatal("later extension mutated an old handle", err)
	}
	if _, err := three.RootAt(13, chain.Hash{1}, f.pin); err != ErrExperimentalV3HeaderMismatch {
		t.Fatal("wrong query header accepted", err)
	}
	if _, err := three.RootAt(13, f.headers[1].Header.HeaderHash, chain.Hash{1}); err != ErrContextFingerprintMismatch {
		t.Fatal("wrong context accepted", err)
	}
	if _, err := three.RootAt(^uint64(0), chain.Hash{1}, f.pin); err != ErrExperimentalV3HeaderUnavailable {
		t.Fatal("overflowing query", err)
	}
	if _, err := json.Marshal(three); err == nil {
		t.Fatal("opaque state encoded as caller authority")
	}
	before := three
	if json.Unmarshal([]byte(`{}`), &three) == nil || three.data != before.data {
		t.Fatal("caller JSON replaced owned state")
	}
	if chain.ValidateHeaderVersion(3) == nil {
		t.Fatal("experimental path activated production v3")
	}
}

func TestExperimentalV3OwnedExtensionIsAtomic(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func([]chain.CandidateV3Header)
		reason  ReasonCode
		outcome Outcome
	}{
		{"changed-root", func(h []chain.CandidateV3Header) { h[1].StateRoot[0] ^= 1 }, ReasonInvalidHash, OutcomeReject},
		{"rehashed-root", func(h []chain.CandidateV3Header) {
			h[1].StateRoot[0] ^= 1
			h[1].Header.HeaderHash, _ = h[1].ComputeHash()
		}, ReasonInvalidSignature, OutcomeReject},
		{"changed-data-hash", func(h []chain.CandidateV3Header) { h[1].Header.DataHash[0] ^= 1 }, ReasonInvalidHash, OutcomeReject},
		{"changed-key", func(h []chain.CandidateV3Header) { h[1].Header.PublicKey[0] ^= 1 }, ReasonInvalidSignature, OutcomeReject},
		{"changed-signature", func(h []chain.CandidateV3Header) { h[1].Header.Signature[0] ^= 1 }, ReasonInvalidSignature, OutcomeReject},
		{"short-signature", func(h []chain.CandidateV3Header) { h[1].Header.Signature = h[1].Header.Signature[:63] }, ReasonInvalidSignature, OutcomeReject},
		{"version-two", func(h []chain.CandidateV3Header) { h[1].Header.Version = 2 }, ReasonUnsupportedHeaderVersion, OutcomeRefused},
		{"unknown-version", func(h []chain.CandidateV3Header) { h[1].Header.Version = 4 }, ReasonUnsupportedHeaderVersion, OutcomeRefused},
		{"wrong-chain", func(h []chain.CandidateV3Header) { h[1].Header.ChainIdentifier = 69 }, ReasonChainIDMismatch, OutcomeReject},
		{"invalid-price", func(h []chain.CandidateV3Header) { h[1].Header.NextWorkPrice = 999 }, ReasonInvalidResourcePrice, OutcomeReject},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := experimentalV3Inputs(t)
			s := experimentalV3New(t, f)
			headers := make([]chain.CandidateV3Header, len(f.headers))
			for i, h := range f.headers {
				headers[i] = cloneExperimentalV3Header(h)
			}
			test.mutate(headers)
			r, next := s.Extend(headers)
			if r.Outcome != test.outcome || r.Reason != test.reason || next.data != s.data || !s.Empty() || containsGuarantee(r.Proven, GuaranteeStateValueInclusion) {
				t.Fatal("failed batch published partial state", r)
			}
		})
	}
	f := experimentalV3Inputs(t)
	s := experimentalV3New(t, f)
	for _, headers := range [][]chain.CandidateV3Header{{f.headers[1]}, {f.headers[0], f.headers[2]}, {f.headers[1], f.headers[0]}} {
		r, next := s.Extend(headers)
		if r.Outcome != OutcomeReject || r.Reason != ReasonHeightNonMonotonic || next.data != s.data {
			t.Fatal("noncontiguous batch accepted", r)
		}
	}
	if r, next := s.Extend(nil); r.Reason != ReasonMissingEvidence || next.data != s.data {
		t.Fatal("empty input accepted", r)
	}
	if r, next := s.Extend(append(f.headers, f.headers[0])); r.Reason != ReasonOversizedHeaders || next.data != s.data {
		t.Fatal("batch limit bypassed", r)
	}
	var zero ExperimentalV3State
	if r, next := zero.Extend(f.headers); r.Reason != ReasonUninitializedState || next.data != nil {
		t.Fatal("zero handle supplied authority", r)
	}
	if _, err := zero.Context(); err != ErrUninitializedState {
		t.Fatal(err)
	}
	if _, ok := zero.HeaderAtHeight(12); ok {
		t.Fatal("zero handle supplied a header")
	}
}

func TestExperimentalV3ProfileAndProducerCoverage(t *testing.T) {
	for _, name := range []string{"expired-profile", "schedule-gap", "timestamp", "producer", "anchor-link", "window-depth"} {
		t.Run(name, func(t *testing.T) {
			f := experimentalV3Inputs(t)
			expected := ReasonProtocolProfileCoverage
			outcome := OutcomeRefused
			switch name {
			case "expired-profile":
				f.profile.ValidThrough = 12
			case "schedule-gap":
				f.schedule, _ = NewProducerSchedule(100, []ProducerCoverage{{FromHeight: 12, ThroughHeight: 12}}, f.schedule.Entries[:1], nil, nil)
				expected = ReasonProducerSetUnknown
			case "timestamp":
				entries := append([]ProducerEntry(nil), f.schedule.Entries...)
				entries[1].TimestampUnix++
				f.schedule, _ = NewProducerSchedule(100, f.schedule.Coverage, entries, nil, nil)
				expected = ReasonUnauthorizedProducer
				outcome = OutcomeReject
			case "producer":
				entries := append([]ProducerEntry(nil), f.schedule.Entries...)
				entries[1].ProducingAddr[0] ^= 1
				f.schedule, _ = NewProducerSchedule(100, f.schedule.Coverage, entries, nil, nil)
				expected = ReasonUnauthorizedProducer
				outcome = OutcomeReject
			case "anchor-link":
				f.profile.Anchor.HeaderHash[0] ^= 1
				expected = ReasonBrokenLinkage
				outcome = OutcomeReject
			case "window-depth":
				f.policy.W = 2
				f.policy.RetainHeaders = 3
				expected = ReasonWindowNotMet
			}
			c, err := ExperimentalV3ContextFor(f.profile, f.policy, f.schedule)
			if err != nil {
				t.Fatal(err)
			}
			f.pin = c.Fingerprint
			s := experimentalV3New(t, f)
			headers := f.headers
			if name == "window-depth" {
				headers = headers[:1]
			}
			r, next := s.Extend(headers)
			if r.Outcome != outcome || r.Reason != expected || next.data != s.data || !s.Empty() {
				t.Fatal("failed profile/schedule decision advanced state", r)
			}
		})
	}
}

func TestExperimentalV3DetachedConcurrentQueries(t *testing.T) {
	f := experimentalV3Inputs(t)
	s := experimentalV3New(t, f)
	r, state := s.Extend(f.headers)
	if r.Outcome != OutcomeAccept {
		t.Fatal(r)
	}
	f.headers[1].Header.PublicKey[0] ^= 1
	f.headers[1].Header.Signature[0] ^= 1
	f.headers[1].StateRoot[0] ^= 1
	h, ok := state.HeaderAtHeight(13)
	if !ok || !ed25519.Verify(h.Header.PublicKey, h.Header.HeaderHash[:], h.Header.Signature) {
		t.Fatal("input mutation reached state")
	}
	h.Header.Signature[0] ^= 1
	h.StateRoot[0] ^= 1
	want, _ := state.HeaderAtHeight(13)
	if reflect.DeepEqual(h, want) {
		t.Fatal("returned header aliases owned bytes")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 32; j++ {
				got, err := state.RootAt(13, want.Header.HeaderHash, f.pin)
				if err != nil || got != want.StateRoot {
					t.Error("concurrent immutable query", err)
				}
				copy, ok := state.HeaderAtHeight(13)
				if !ok {
					t.Error("missing header")
				}
				copy.Header.PublicKey[0] ^= 1
			}
		}()
	}
	wg.Wait()
}
