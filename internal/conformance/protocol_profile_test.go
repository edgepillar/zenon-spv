package conformance_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func transitionFixture(t *testing.T) (momentumCorpus, []chain.Header, verify.Policy) {
	t.Helper()
	c := loadCorpus(t)
	detailed, err := fetchVectors(t, c.Transition.Vectors)
	if err != nil {
		t.Fatal(err)
	}
	headers := make([]chain.Header, len(detailed))
	for i, d := range detailed {
		headers[i] = d.Header
		if !reflect.DeepEqual(d.Header, c.Transition.Vectors[i].Header) {
			t.Fatalf("transition header %d differs from node", i)
		}
	}
	return c, headers, verify.Policy{W: 5, ProtocolProfile: &verify.ProtocolProfile{
		Version: 1, Anchor: c.Transition.Anchor, ValidThrough: headers[len(headers)-1].Height,
		V2FromHeight: c.Transition.V2FromHeight, Source: "synthetic node-derived conformance series",
	}}
}

func TestNodeTransitionProfileAndResume(t *testing.T) {
	c, headers, policy := transitionFixture(t)
	policy.W = 1
	state := verify.NewHeaderState(c.Transition.Anchor, policy)
	result, before := verify.VerifyHeaders(headers[:2], state, policy)
	if result.Outcome != verify.OutcomeAccept {
		t.Fatal(result)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := verify.SaveHeaderState(path, before); err != nil {
		t.Fatal(err)
	}
	loaded, err := verify.LoadOrInit(path, c.Transition.Anchor, policy)
	if err != nil {
		t.Fatal(err)
	}
	result, after := verify.VerifyHeaders(headers[2:], loaded, policy)
	if result.Outcome != verify.OutcomeAccept || !slices.Contains(result.TrustAssumptions, verify.TrustExternalProtocolProfile) {
		t.Fatal(result)
	}
	assertBoundedGuarantees(t, result)
	if err := verify.SaveHeaderState(path, after); err != nil {
		t.Fatal(err)
	}
	resumed, err := verify.LoadOrInit(path, c.Transition.Anchor, policy)
	if err != nil || !reflect.DeepEqual(resumed, after) {
		t.Fatalf("v2 resume differs: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil || schema.Version != 2 {
		t.Fatalf("profile state must use schema 2: %v", err)
	}
	for _, missing := range []bool{true, false} {
		other := policy
		if missing {
			other.ProtocolProfile = nil
		} else {
			changed := *policy.ProtocolProfile
			changed.ValidThrough++
			other.ProtocolProfile = &changed
		}
		if _, err := verify.LoadOrInit(path, c.Transition.Anchor, other); !errors.Is(err, verify.ErrProtocolProfileMismatch) {
			t.Fatalf("resume with different profile: %v", err)
		}
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, unchanged) {
		t.Fatal("refused resume modified persisted state")
	}
	// A profile captured by the state must not alias the caller's config.
	policy.ProtocolProfile.Source = "changed caller configuration"
	if before.ProtocolProfile.Source == policy.ProtocolProfile.Source {
		t.Fatal("state aliases caller's protocol profile")
	}
}

func TestNodeTransitionActivationBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(*verify.Policy)
		outcome verify.Outcome
		reason  verify.ReasonCode
	}{
		{"missing", func(p *verify.Policy) { p.ProtocolProfile = nil }, verify.OutcomeRefused, verify.ReasonProtocolProfileRequired},
		{"v2-too-early", func(p *verify.Policy) { p.ProtocolProfile.V2FromHeight++ }, verify.OutcomeReject, verify.ReasonHeaderVersionInactive},
		{"v1-too-late", func(p *verify.Policy) { p.ProtocolProfile.V2FromHeight-- }, verify.OutcomeReject, verify.ReasonHeaderVersionInactive},
		{"v1-only", func(p *verify.Policy) { p.ProtocolProfile.V2FromHeight = 0 }, verify.OutcomeReject, verify.ReasonHeaderVersionInactive},
		{"coverage-ended", func(p *verify.Policy) { p.ProtocolProfile.ValidThrough-- }, verify.OutcomeRefused, verify.ReasonProtocolProfileCoverage},
		{"wrong-network", func(p *verify.Policy) { p.ProtocolProfile.Anchor.ChainID++ }, verify.OutcomeRefused, verify.ReasonProtocolProfileMismatch},
		{"wrong-anchor-hash", func(p *verify.Policy) { p.ProtocolProfile.Anchor.HeaderHash[0] ^= 1 }, verify.OutcomeRefused, verify.ReasonProtocolProfileMismatch},
		{"wrong-anchor-height", func(p *verify.Policy) { p.ProtocolProfile.Anchor.Height++ }, verify.OutcomeRefused, verify.ReasonProtocolProfileMismatch},
		{"unknown-profile", func(p *verify.Policy) { p.ProtocolProfile.Version++ }, verify.OutcomeRefused, verify.ReasonInvalidProtocolProfile},
		{"missing-provenance", func(p *verify.Policy) { p.ProtocolProfile.Source = "" }, verify.OutcomeRefused, verify.ReasonInvalidProtocolProfile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, headers, policy := transitionFixture(t)
			tc.edit(&policy)
			state := verify.NewHeaderState(c.Transition.Anchor, policy)
			result, after := verify.VerifyHeaders(headers, state, policy)
			if result.Outcome != tc.outcome || result.Reason != tc.reason || len(result.Proven) != 0 || !reflect.DeepEqual(after, state) {
				t.Fatalf("unexpected activation result or state change: %s", result)
			}
		})
	}
}

func TestNodeV2PricesAndBundleRoundTrip(t *testing.T) {
	c, headers, policy := transitionFixture(t)
	bundle := proof.HeaderBundle{Version: proof.WireVersion, ChainID: c.Transition.Anchor.ChainID,
		ClaimedGenesis: c.Transition.Anchor.HeaderHash, Headers: headers}
	raw, err := proof.MarshalHeaderBundleJSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := proof.UnmarshalHeaderBundleJSON(raw)
	if err != nil || !reflect.DeepEqual(decoded.Headers, headers) {
		t.Fatalf("bundle dropped prices: %v", err)
	}
	for _, fusion := range []bool{true, false} {
		for _, value := range []uint64{0, 999, 1000, 1<<53 + 1, ^uint64(0)} {
			changed := slices.Clone(headers)
			if fusion {
				changed[3].NextFusionPrice = value
			} else {
				changed[3].NextWorkPrice = value
			}
			state := verify.NewHeaderState(c.Transition.Anchor, policy)
			result, after := verify.VerifyHeaders(changed, state, policy)
			want := verify.ReasonInvalidHash
			if value < 1000 {
				want = verify.ReasonInvalidResourcePrice
			}
			if result.Outcome != verify.OutcomeReject || result.Reason != want || !reflect.DeepEqual(after, state) {
				t.Fatalf("fusion=%v price=%d: %s", fusion, value, result)
			}
		}
	}
	for _, v := range c.Vectors {
		if v.Header.Version != 2 {
			continue
		}
		anchor := verify.GenesisTrustRoot{ChainID: v.Header.ChainIdentifier, Height: v.Header.Height - 1, HeaderHash: v.Header.PreviousHash}
		p := verify.Policy{W: 1, ProtocolProfile: &verify.ProtocolProfile{Version: 1, Anchor: anchor,
			V2FromHeight: v.Header.Height, ValidThrough: v.Header.Height, Source: "synthetic standalone vector"}}
		result, _ := verify.VerifyHeaders([]chain.Header{v.Header}, verify.NewHeaderState(anchor, p), p)
		if v.Header.NextFusionPrice == 0 {
			if result.Reason != verify.ReasonInvalidResourcePrice || result.Outcome != verify.OutcomeReject {
				t.Fatal(result)
			}
		} else if result.Outcome != verify.OutcomeAccept {
			t.Fatal(result)
		}
	}
}

func TestNodeTransitionRetainedPolicyCannotBeDropped(t *testing.T) {
	c, headers, policy := transitionFixture(t)
	result, state := verify.VerifyHeaders(headers, verify.NewHeaderState(c.Transition.Anchor, policy), policy)
	if result.Outcome != verify.OutcomeAccept {
		t.Fatal(result)
	}
	evidence := proof.CommitmentEvidence{Height: headers[0].Height, Target: c.Transition.Vectors[0].Content[0],
		Flat: &proof.FlatContentEvidence{SortedHeaders: c.Transition.Vectors[0].Content}}
	result = verify.VerifyCommitment(state, evidence, policy)
	if result.Outcome != verify.OutcomeAccept || !slices.Contains(result.TrustAssumptions, verify.TrustExternalProtocolProfile) {
		t.Fatal(result)
	}
	noProfile := policy
	noProfile.ProtocolProfile = nil
	results := []verify.Result{
		verify.VerifyCommitment(state, evidence, noProfile),
		verify.AuthorizeRetainedWindow(state, verify.VerifyOptions{Policy: noProfile}),
		verify.VerifyStateValue(state, proof.StateValueProof{}, noProfile),
	}
	for _, r := range results {
		if r.Outcome != verify.OutcomeRefused || r.Reason != verify.ReasonProtocolProfileMismatch || len(r.Proven) != 0 {
			t.Fatalf("dependent path dropped the profile: %s", r)
		}
	}
	// Validate every stored header before reducing the window.
	path := filepath.Join(t.TempDir(), "state.json")
	if err := verify.SaveHeaderState(path, state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	changedProfile := *policy.ProtocolProfile
	changedProfile.V2FromHeight-- // the old v1 header at 2002 becomes invalid
	wire["protocol_profile"], err = json.Marshal(changedProfile)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	policy.W, policy.ProtocolProfile = 0, &changedProfile
	if _, err := verify.LoadOrInit(path, c.Transition.Anchor, policy); !errors.Is(err, verify.ErrHeaderVersionInactive) {
		t.Fatalf("invalid retained prefix escaped truncation: %v", err)
	}
}

func TestNodeV2MissingAndTamperedWirePrices(t *testing.T) {
	for _, field := range []string{"nextFusionPrice", "nextWorkPrice"} {
		for _, value := range []json.RawMessage{nil, json.RawMessage(`null`), json.RawMessage(`1000`)} {
			v := loadCorpus(t).Vectors[7]
			for _, rpc := range []bool{false, true} {
				raw := v.Momentum
				if !rpc {
					var err error
					raw, err = json.Marshal(v.Header)
					if err != nil {
						t.Fatal(err)
					}
				}
				var wire map[string]json.RawMessage
				if err := json.Unmarshal(raw, &wire); err != nil {
					t.Fatal(err)
				}
				if value == nil {
					delete(wire, field)
				} else {
					wire[field] = value
				}
				raw, err := json.Marshal(wire)
				if err != nil {
					t.Fatal(err)
				}
				if rpc {
					v.Momentum = raw
					got, err := fetchVectors(t, []momentumVector{loadCorpus(t).Chain.Vectors[0], v})
					if err == nil || len(got) != 0 {
						t.Fatal("bad v2 RPC price returned partial evidence")
					}
				} else {
					var h chain.Header
					err := json.Unmarshal(raw, &h)
					if string(value) == "1000" {
						if err != nil || h.ComputeHash() == h.HeaderHash {
							t.Fatal("price tampering was not bound to the hash")
						}
					} else if err == nil {
						t.Fatal("missing/null bundle or state price was silently defaulted")
					}
				}
			}
		}
	}
}
