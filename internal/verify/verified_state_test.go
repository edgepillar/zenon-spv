package verify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func verifiedStateFixture(t *testing.T) (VerifiedState, []chain.Header, proof.CommitmentEvidence, VerifyOptions) {
	t.Helper()
	anchor := GenesisTrustRoot{ChainID: 3, Height: 100, HeaderHash: chain.Hash{1}}
	member := chain.AccountHeader{Address: chain.Address{1}, Height: 1, Hash: chain.Hash{2}}
	flat := []chain.AccountHeader{member}
	previous := anchor
	headers := make([]chain.Header, 3)
	for i := range headers {
		headers[i] = boundaryHeader(previous, 101+uint64(i), chain.MomentumContentHash(flat))
		previous.Height, previous.HeaderHash = headers[i].Height, headers[i].HeaderHash
	}
	policy := DefaultPolicy()
	policy.W = 2
	policy.ProtocolProfile = &ProtocolProfile{Version: 1, Anchor: anchor, ValidThrough: 110, Source: "synthetic fixture"}
	opts := VerifyOptions{Policy: policy}
	initial, err := NewVerifiedState(anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	r, state := initial.Extend(headers)
	if r.Outcome != OutcomeAccept || !initial.Empty() {
		t.Fatalf("fixture extension failed or mutated the initial handle: %s", r)
	}
	assertHasTrustAssumption(t, r.TrustAssumptions, TrustConfiguredAnchor)
	return state, headers, proof.CommitmentEvidence{Height: 101, Target: member,
		Flat: &proof.FlatContentEvidence{SortedHeaders: flat}}, opts
}

func TestVerifiedState_ZeroAndJSONCannotProvideEvidence(t *testing.T) {
	var zero VerifiedState
	r, after := zero.Extend([]chain.Header{{}})
	results := []Result{r, zero.VerifyCommitment(proof.CommitmentEvidence{}),
		zero.VerifyStateValue(proof.StateValueProof{}), zero.VerifySegment(proof.AccountSegment{}, nil).Blocks[0]}
	for _, result := range results {
		if result.Outcome != OutcomeRefused || result.Reason != ReasonUninitializedState || len(result.Proven) != 0 {
			t.Fatalf("zero handle granted evidence: %s", result)
		}
	}
	if !after.Empty() || !errors.Is(zero.Save(filepath.Join(t.TempDir(), "state.json")), ErrUninitializedState) {
		t.Fatal("zero handle advanced or saved")
	}
	state, _, _, _ := verifiedStateFixture(t)
	before := state.Snapshot()
	if _, err := json.Marshal(state); err == nil {
		t.Fatal("opaque state silently serialized")
	}
	if err := json.Unmarshal([]byte(`{"RetainedWindow":[{"height":999}]}`), &state); err == nil {
		t.Fatal("opaque state accepted direct deserialization")
	}
	if !reflect.DeepEqual(before, state.Snapshot()) {
		t.Fatal("failed decoding changed the existing handle")
	}
}

func TestVerifiedState_OwnsInputsViewsAndPolicy(t *testing.T) {
	state, headers, evidence, opts := verifiedStateFixture(t)
	before := state.Snapshot()
	headers[2].PublicKey[0] ^= 1
	headers[2].Signature[0] ^= 1
	headers[2].Height = 0
	opts.Policy.W = 0
	opts.Policy.ProtocolProfile.ValidThrough = 0
	tip, _ := state.Tip()
	tip.Signature[0] ^= 1
	tip.PublicKey[0] ^= 1
	view := state.Snapshot()
	view.RetainedWindow[0].ContentHash = chain.Hash{}
	view.RetainedWindow[0].PublicKey[0] ^= 1
	view.RetainedWindow[0].Signature[0] ^= 1
	view.ProtocolProfile.Source = "changed"
	view.Genesis = GenesisTrustRoot{}
	if !reflect.DeepEqual(before, state.Snapshot()) {
		t.Fatal("caller mutation changed verified state")
	}
	if r := state.VerifyCommitment(evidence); r.Outcome != OutcomeAccept {
		t.Fatalf("caller mutation invalidated owned evidence: %s", r)
	}
	evidence.Height = 103
	if r := state.VerifyCommitment(evidence); r.Outcome != OutcomeRefused || r.Reason != ReasonInsufficientFinality {
		t.Fatalf("query bypassed the captured depth policy: %s", r)
	}
}

func TestVerifiedState_ExtensionsAreTransactional(t *testing.T) {
	state, _, _, _ := verifiedStateFixture(t)
	before := state.Snapshot()
	tip, _ := state.Tip()
	anchor := GenesisTrustRoot{ChainID: tip.ChainIdentifier, Height: tip.Height, HeaderHash: tip.HeaderHash}
	valid := boundaryHeader(anchor, 104, chain.Hash{2})
	invalid := valid
	invalid.Signature = nil
	r, failed := state.Extend([]chain.Header{invalid})
	if r.Outcome != OutcomeReject || failed != state || !reflect.DeepEqual(before, state.Snapshot()) {
		t.Fatalf("failed extension changed state: %s", r)
	}
	r, accepted := state.Extend([]chain.Header{valid})
	if r.Outcome != OutcomeAccept || accepted == state || !reflect.DeepEqual(before, state.Snapshot()) {
		t.Fatalf("accepted extension changed its predecessor: %s", r)
	}
	view := accepted.Snapshot()
	view.RetainedWindow[0].PublicKey[0] ^= 1
	if !reflect.DeepEqual(before, state.Snapshot()) {
		t.Fatal("successor view mutated predecessor")
	}
}

func TestVerifiedState_ConstructorRejectsInvalidInputs(t *testing.T) {
	anchor := GenesisTrustRoot{ChainID: 3, Height: 100, HeaderHash: chain.Hash{1}}
	for _, opts := range []VerifyOptions{
		{Policy: Policy{W: ^uint64(0)}},
		{Policy: Policy{W: uint64(MaxPersistedHeaders)}},
		{Policy: Policy{MaxHeaders: -1}},
		{Policy: Policy{MaxBundleBytes: -1}},
		{ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired}},
		{ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthMode(7)}},
		{ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: (*ScheduleAuthorizer)(nil)}},
	} {
		if state, err := NewVerifiedState(anchor, opts); err == nil || state.data != nil {
			t.Fatal("invalid configuration created a handle")
		}
	}
	for _, bad := range []GenesisTrustRoot{{}, {HeaderHash: chain.Hash{1}}} {
		if _, err := NewVerifiedState(bad, VerifyOptions{}); err == nil {
			t.Fatal("invalid anchor created a handle")
		}
	}
}

func TestVerifiedState_TrustedResumeKeepsItsTrustBoundary(t *testing.T) {
	state, _, evidence, opts := verifiedStateFixture(t)
	if _, err := LoadTrustedState("", state.Snapshot().Genesis, opts); err == nil {
		t.Fatal("empty path silently initialized a state")
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	resumed, err := LoadTrustedState(path, state.Snapshot().Genesis, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := resumed.VerifyCommitment(evidence)
	if r.Outcome != OutcomeAccept {
		t.Fatal(r)
	}
	assertHasTrustAssumption(t, r.TrustAssumptions, TrustConfiguredAnchor)
	assertHasTrustAssumption(t, r.TrustAssumptions, TrustPersistedState)
	assertHasTrustAssumption(t, r.TrustAssumptions, TrustExternalProtocolProfile)
	for _, tag := range state.VerifyCommitment(evidence).TrustAssumptions {
		if tag == TrustPersistedState {
			t.Fatal("fresh verification incorrectly reports a resumed file")
		}
	}
	snapshot := state.Snapshot()
	snapshot.RetainedWindow[0].Signature[0] ^= 1
	body, err := json.Marshal(persistedState{Version: profileStateFileVersion, Genesis: snapshot.Genesis,
		ProtocolProfile: snapshot.ProtocolProfile, Window: snapshot.RetainedWindow, Capacity: snapshot.Capacity})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if bad, err := LoadTrustedState(path, snapshot.Genesis, opts); err == nil || bad.data != nil {
		t.Fatal("corrupt persisted state became a verified handle")
	}
}

func TestVerifiedState_FreezesOperatorScheduleAndReauthorizesResume(t *testing.T) {
	anchor, headers, _ := buildChain(t, 6)
	schedule := fixtureSchedule(t, 6)
	opts := VerifyOptions{Policy: Policy{W: 2}, ProducerAuth: ProducerAuthOptions{
		Mode: ProducerAuthRequired, Authorizer: NewScheduleAuthorizer(schedule)}}
	state, err := NewVerifiedState(anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	schedule.Entries[3].ProducingAddr = chain.Address{}
	schedule.ScheduleHash = computeScheduleHash(schedule.ChainID, schedule.Coverage, schedule.Entries)
	r, state := state.Extend(headers)
	if r.Outcome != OutcomeAccept {
		t.Fatalf("external schedule mutation changed captured authorization: %s", r)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	_, err = LoadTrustedState(path, anchor, opts)
	var authError *StateAuthorizationError
	if !errors.As(err, &authError) || authError.Result.Outcome != OutcomeReject || authError.Result.Reason != ReasonUnauthorizedProducer {
		t.Fatalf("resume did not reauthorize under the new schedule: %v", err)
	}
}

type mutatingKeyAuthorizer struct{ keys [][]byte }

func (a *mutatingKeyAuthorizer) Authorize(_, _ uint64, key []byte) ProducerDecision {
	key[0] ^= 1
	a.keys = append(a.keys, key)
	return ProducerAuthorized
}

func (*mutatingKeyAuthorizer) Source() ProducerSource { return ProducerSourceOperatorAttested }

func TestVerifiedState_AuthorizerCannotRetainStateMemory(t *testing.T) {
	anchor, headers, _ := buildChain(t, 6)
	auth := &mutatingKeyAuthorizer{}
	opts := VerifyOptions{Policy: Policy{W: 2}, ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: auth}}
	state, err := NewVerifiedState(anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	r, state := state.Extend(headers)
	if r.Outcome != OutcomeAccept {
		t.Fatal(r)
	}
	for _, key := range auth.keys {
		key[0] ^= 1
	}
	if err := state.Save(filepath.Join(t.TempDir(), "state.json")); err != nil {
		t.Fatalf("authorizer corrupted verified keys: %v", err)
	}
}

func TestVerifiedState_ConcurrentReadersOwnTheirSnapshots(t *testing.T) {
	state, _, evidence, _ := verifiedStateFixture(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				view := state.Snapshot()
				view.RetainedWindow[0].PublicKey[0] ^= 1
				view.ProtocolProfile.ValidThrough = 0
				if r := state.VerifyCommitment(evidence); r.Outcome != OutcomeAccept {
					t.Errorf("snapshot mutation affected a concurrent reader: %s", r)
				}
			}
		}()
	}
	wg.Wait()
}
