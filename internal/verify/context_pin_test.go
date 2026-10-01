package verify

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestRequireContextFingerprintUsesOwnedSettings(t *testing.T) {
	state, headers, evidence, opts := verifiedStateFixture(t)
	view, err := state.VerificationContext()
	if err != nil {
		t.Fatal(err)
	}
	pin := *view.Fingerprint
	before := state.VerifyCommitment(evidence)
	initial, err := NewVerifiedState(view.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTrustedState(path, view.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []VerifiedState{initial, state, loaded} {
		if err := s.RequireContextFingerprint(pin); err != nil {
			t.Fatalf("state history changed the captured settings: %v", err)
		}
	}
	*view.Fingerprint = chain.Hash{}
	view.Policy.W++
	opts.Policy.W++
	changed, err := NewVerifiedState(view.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := changed.RequireContextFingerprint(pin); !errors.Is(err, ErrContextFingerprintMismatch) {
		t.Fatal("changed policy matched an older pin")
	}
	if err := state.RequireContextFingerprint(*view.Fingerprint); !errors.Is(err, ErrContextFingerprintMismatch) {
		t.Fatal("caller-owned diagnostic changed the pin check")
	}
	if err := state.RequireContextFingerprint(pin); err != nil || !reflect.DeepEqual(before, state.VerifyCommitment(evidence)) {
		t.Fatal("checking settings changed proof guarantees")
	}
	result, extended := initial.Extend(headers)
	if result.Outcome != OutcomeAccept || extended.RequireContextFingerprint(pin) != nil {
		t.Fatal("extension changed the configuration pin")
	}
}

func TestRequireContextFingerprintRejectsUnavailableIdentity(t *testing.T) {
	if err := (VerifiedState{}).RequireContextFingerprint(chain.Hash{}); !errors.Is(err, ErrUninitializedState) {
		t.Fatal("uninitialized state satisfied a pin")
	}
	authorizer := &contextAuthorizer{}
	state, err := NewVerifiedState(GenesisTrustRoot{ChainID: 3, Height: 100, HeaderHash: chain.Hash{1}},
		VerifyOptions{Policy: DefaultPolicy(), ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: authorizer}})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.RequireContextFingerprint(chain.Hash{}); !errors.Is(err, ErrContextFingerprintUnavailable) || authorizer.sourceCalls != 1 {
		t.Fatal("custom authorizer acquired a settings identity or was called again")
	}
}
