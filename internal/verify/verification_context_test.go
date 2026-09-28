package verify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func contextFor(t *testing.T, anchor GenesisTrustRoot, opts VerifyOptions) VerificationContext {
	t.Helper()
	s, err := NewVerifiedState(anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.VerificationContext()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVerificationContextZeroAndLifecycle(t *testing.T) {
	if c, err := (VerifiedState{}).VerificationContext(); !errors.Is(err, ErrUninitializedState) || c.Fingerprint != nil {
		t.Fatal("zero handle produced a fingerprint")
	}
	if raw, err := (VerifiedState{}).VerificationContextJSON(); !errors.Is(err, ErrUninitializedState) || raw != nil {
		t.Fatal("zero handle produced context JSON")
	}
	state, headers, _, opts := verifiedStateFixture(t)
	anchor := state.Snapshot().Genesis
	want := contextFor(t, anchor, opts)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	resumed, err := LoadTrustedState(path, anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	_, failed := resumed.Extend(headers) // Old heights cannot extend the tip.
	for _, s := range []VerifiedState{state, resumed, failed} {
		got, err := s.VerificationContext()
		if err != nil || !reflect.DeepEqual(want, got) {
			t.Fatalf("state progress or resume changed captured settings: %v", err)
		}
	}
}

func TestVerificationContextBindsEveryPolicyLimit(t *testing.T) {
	anchor := GenesisTrustRoot{ChainID: 3, Height: 100, HeaderHash: chain.Hash{1}}
	base := VerifyOptions{Policy: DefaultPolicy()}
	want := *contextFor(t, anchor, base).Fingerprint
	// Every scalar Policy field must affect the fingerprint. This also makes
	// a future policy addition require an explicit context-format decision.
	policyType := reflect.TypeOf(base.Policy)
	for i := range policyType.NumField() {
		name := policyType.Field(i).Name
		if name == "ProtocolProfile" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			opts := base
			field := reflect.ValueOf(&opts.Policy).Elem().Field(i)
			switch field.Kind() {
			case reflect.Int, reflect.Int64:
				field.SetInt(field.Int() + 1)
			case reflect.Uint64:
				field.SetUint(field.Uint() + 1)
			default:
				t.Fatalf("new policy field %s needs a context-format decision", name)
			}
			if *contextFor(t, anchor, opts).Fingerprint == want {
				t.Fatal("policy change did not change the fingerprint")
			}
		})
	}
	for _, changed := range []GenesisTrustRoot{
		{ChainID: 4, Height: 100, HeaderHash: anchor.HeaderHash},
		{ChainID: 3, Height: 101, HeaderHash: anchor.HeaderHash},
		{ChainID: 3, Height: 100, HeaderHash: chain.Hash{2}},
	} {
		if *contextFor(t, changed, base).Fingerprint == want {
			t.Fatal("anchor change did not change the fingerprint")
		}
	}
}

func TestVerificationContextProfileRulesExcludePrivateLabels(t *testing.T) {
	profileType := reflect.TypeOf(ProtocolProfile{})
	fields := []string{"Version", "Anchor", "ValidThrough", "V2FromHeight", "Source"}
	if profileType.NumField() != len(fields) {
		t.Fatal("new profile fields need an explicit context-format and privacy decision")
	}
	for _, name := range fields {
		if _, ok := profileType.FieldByName(name); !ok {
			t.Fatalf("profile field %s changed; review the context format", name)
		}
	}
	state, _, _, opts := verifiedStateFixture(t)
	anchor := state.Snapshot().Genesis
	want := contextFor(t, anchor, opts)
	for _, mutate := range []func(*ProtocolProfile){
		func(p *ProtocolProfile) { p.ValidThrough++ },
		func(p *ProtocolProfile) { p.V2FromHeight = 103 },
	} {
		changed := opts
		changed.Policy.ProtocolProfile = cloneProtocolProfile(opts.Policy.ProtocolProfile)
		mutate(changed.Policy.ProtocolProfile)
		if *contextFor(t, anchor, changed).Fingerprint == *want.Fingerprint {
			t.Fatal("activation rules did not change the fingerprint")
		}
	}
	legacy := opts
	legacy.Policy.ProtocolProfile = nil
	if *contextFor(t, anchor, legacy).Fingerprint == *want.Fingerprint {
		t.Fatal("legacy v1-only context collided with an explicit profile")
	}
	opts.Policy.ProtocolProfile.Source = "PRIVATE_AUDIT_LABEL https://private.invalid/observations"
	got := contextFor(t, anchor, opts)
	raw, err := json.Marshal(got)
	if err != nil || strings.Contains(string(raw), "PRIVATE_AUDIT_LABEL") || strings.Contains(string(raw), "private.invalid") {
		t.Fatalf("profile metadata reached the public context: %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatal("private provenance label changed the rules fingerprint")
	}
	// The privacy-filtered fingerprint is not a file-compatibility token.
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustedState(path, anchor, opts); !errors.Is(err, ErrProtocolProfileMismatch) {
		t.Fatalf("equal rules fingerprints bypassed full profile matching: %v", err)
	}
}

func TestVerificationContextOwnsViewsAndScheduleIdentity(t *testing.T) {
	anchor := GenesisTrustRoot{ChainID: 3, Height: 100, HeaderHash: chain.Hash{1}}
	schedule := fixtureSchedule(t, 3)
	schedule.SourcePeers = []string{"PRIVATE_PEER"}
	schedule.SourceHeights = map[string]uint64{"PRIVATE_PEER": 999}
	opts := VerifyOptions{Policy: DefaultPolicy(), ProducerAuth: ProducerAuthOptions{
		Mode: ProducerAuthRequired, Authorizer: NewScheduleAuthorizer(schedule),
	}}
	state, err := NewVerifiedState(anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	before, err := state.VerificationContext()
	if err != nil || before.Fingerprint == nil || before.Producer.ScheduleHash == nil || *before.Producer.ScheduleHash != schedule.ScheduleHash {
		t.Fatalf("missing validated schedule identity: %v", err)
	}
	raw, err := json.Marshal(before)
	if err != nil || strings.Contains(string(raw), "PRIVATE_PEER") || strings.Contains(string(raw), "source_heights") {
		t.Fatalf("schedule metadata reached context: %v", err)
	}
	view, _ := state.VerificationContext()
	*view.Fingerprint = chain.Hash{}
	*view.Producer.ScheduleHash = chain.Hash{}
	view.Policy.W = 0
	schedule.Entries[0].TimestampUnix++
	schedule.ScheduleHash = computeScheduleHash(schedule.ChainID, schedule.Coverage, schedule.Entries)
	after, _ := state.VerificationContext()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("caller-owned schedule or view changed the captured context")
	}
	if *contextFor(t, anchor, opts).Fingerprint == *before.Fingerprint {
		t.Fatal("a different validated schedule reused the same context fingerprint")
	}
	opts.ProducerAuth.Mode = ProducerAuthDisabled
	disabled := contextFor(t, anchor, opts)
	if disabled.Producer.ScheduleHash != nil || *disabled.Fingerprint == *before.Fingerprint {
		t.Fatal("disabled authorization retained the required schedule's identity")
	}

	anchor.ChainID = MainnetChainID
	mainnet := contextFor(t, anchor, VerifyOptions{Policy: DefaultPolicy()})
	if !reflect.DeepEqual(mainnet.Checkpoints, MainnetCheckpoints()) {
		t.Fatal("context omitted applicable embedded checkpoints")
	}
	mainnet.Checkpoints[0].HeaderHash[0] ^= 1
	if contextFingerprint(mainnet) == *mainnet.Fingerprint {
		t.Fatal("checkpoint change did not affect the fingerprint")
	}
	fresh := contextFor(t, anchor, VerifyOptions{Policy: DefaultPolicy()})
	if !reflect.DeepEqual(fresh.Checkpoints, MainnetCheckpoints()) || *fresh.Fingerprint != *mainnet.Fingerprint {
		t.Fatal("context view changed embedded checkpoints")
	}
}

type contextAuthorizer struct{ sourceCalls int }

func (a *contextAuthorizer) Source() ProducerSource {
	a.sourceCalls++
	return ProducerSourceOperatorAttested
}

func (*contextAuthorizer) Authorize(uint64, uint64, []byte) ProducerDecision {
	panic("context inspection must not invoke the authorization callback")
}

func TestVerificationContextCustomAuthorizerIsNotFingerprintable(t *testing.T) {
	anchor := GenesisTrustRoot{ChainID: 3, Height: 100, HeaderHash: chain.Hash{1}}
	a := &contextAuthorizer{}
	state, err := NewVerifiedState(anchor, VerifyOptions{Policy: DefaultPolicy(),
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: a}})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		c, err := state.VerificationContext()
		if err != nil || c.Fingerprint != nil || c.FingerprintStatus != "unavailable_custom_authorizer" ||
			c.Producer.Kind != "custom" || c.Producer.ScheduleHash != nil || c.Producer.Source != "OperatorAttested" {
			t.Fatalf("custom callback received a reproducible identity: %+v err=%v", c, err)
		}
	}
	if a.sourceCalls != 1 {
		t.Fatal("context inspection invoked a caller callback after construction")
	}
}

func TestVerificationContextIndependentGolden(t *testing.T) {
	state, _, _, _ := verifiedStateFixture(t)
	entries := []ProducerEntry{
		{Height: 101, TimestampUnix: 1700000010, ProducingAddr: chain.Address{1}},
		{Height: 102, TimestampUnix: 1700000020, ProducingAddr: chain.Address{1}},
	}
	schedule, err := NewProducerSchedule(1, []ProducerCoverage{{101, 102}}, entries, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	mainnet, err := NewVerifiedState(GenesisTrustRoot{ChainID: 1, Height: 100, HeaderHash: chain.Hash{1}},
		VerifyOptions{Policy: DefaultPolicy(), ProducerAuth: ProducerAuthOptions{
			Mode: ProducerAuthRequired, Authorizer: NewScheduleAuthorizer(schedule),
		}})
	if err != nil {
		t.Fatal(err)
	}
	for file, state := range map[string]VerifiedState{"v1.json": state, "v1-schedule-checkpoints.json": mainnet} {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("../testdata/verification-context", file))
			if err != nil {
				t.Fatal(err)
			}
			var want, got VerificationContext
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}
			actual, err := state.VerificationContextJSON()
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(actual, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("context differs from independent Python vector: got=%+v want=%+v", got, want)
			}
		})
	}
}
