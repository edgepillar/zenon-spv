package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// signLegacyHeaders intentionally applies the v1 preimage to arbitrary
// version numbers. These are adversarial fixtures, not v2/v3 encodings.
func signLegacyHeaders(headers []chain.Header, key ed25519.PrivateKey) {
	for i := range headers {
		if i > 0 {
			headers[i].PreviousHash = headers[i-1].HeaderHash
		}
		headers[i].HeaderHash = headers[i].ComputeHash()
		headers[i].Signature = ed25519.Sign(key, headers[i].HeaderHash[:])
	}
}

func requireUnsupportedHeader(t *testing.T, r Result) {
	t.Helper()
	if r.Outcome != OutcomeRefused || r.Reason != ReasonUnsupportedHeaderVersion {
		t.Fatalf("expected REFUSED/UnsupportedHeaderVersion, got %s", r)
	}
	if len(r.Proven) != 0 {
		t.Fatalf("unsupported version reported proven guarantees: %v", r.Proven)
	}
}

func TestVerifyHeaders_UnsupportedVersionWithValidLegacySignature(t *testing.T) {
	for _, version := range []uint64{0, 3, ^uint64(0)} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			genesis, headers, key := buildChain(t, 6)
			headers[5].Version = version
			signLegacyHeaders(headers, key)
			policy := Policy{W: WindowLow}
			state := NewHeaderState(genesis, policy)
			r, after := VerifyHeaders(headers, state, policy)
			requireUnsupportedHeader(t, r)
			if !reflect.DeepEqual(after, state) {
				t.Error("unsupported header changed retained state")
			}
		})
	}
}

func TestVerifyHeaders_UnsupportedRetainedVersionCannotBeEvictedIntoAcceptance(t *testing.T) {
	for _, index := range []int{0, 3, 5} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			genesis, headers, key := buildChain(t, 9)
			headers[index].Version = 3
			signLegacyHeaders(headers, key)
			policy := Policy{W: WindowLow}
			state := NewHeaderState(genesis, policy)
			for _, h := range headers[:6] {
				state.Append(h)
			}
			r, after := VerifyHeaders(headers[6:], state, policy)
			requireUnsupportedHeader(t, r)
			if !reflect.DeepEqual(after, state) {
				t.Error("unsupported retained header changed state")
			}
		})
	}
}

func TestVerifyCommitment_UnsupportedRetainedVersion(t *testing.T) {
	for _, index := range []int{0, 3, 6} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			state, evidence, _ := commitmentFixture(t)
			state.RetainedWindow[index].Version = 3
			signLegacyHeaders(state.RetainedWindow, ed25519.NewKeyFromSeed(fixtureSeed))
			requireUnsupportedHeader(t, VerifyCommitment(state, evidence, commitmentFixturePolicy()))
		})
	}
}

func TestVerifySegment_UnsupportedMomentumVersion(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	state.RetainedWindow[1].Version = 3
	result := VerifySegment(state, segment, commitments, Policy{W: WindowLow})
	if len(result.Blocks) != len(segment.Blocks) {
		t.Fatalf("result count = %d, want %d", len(result.Blocks), len(segment.Blocks))
	}
	requireUnsupportedHeader(t, result.Blocks[0])
	if result.Blocks[1].Outcome != OutcomeRefused {
		t.Fatalf("child of refused block must refuse, got %s", result.Blocks[1])
	}
}

func TestVerifyStateValue_UnsupportedMomentumVersion(t *testing.T) {
	state, evidence := stateValueFixture(t)
	state.RetainedWindow[1].Version = 3
	r := VerifyStateValue(state, evidence, Policy{W: 2})
	requireUnsupportedHeader(t, r)
	if len(r.TrustAssumptions) != 0 {
		t.Error("unsupported retained window must not be trusted")
	}
}

func TestAuthorizeRetainedWindow_UnsupportedVersionWithAuthDisabled(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)
	state := NewHeaderState(genesis, Policy{W: WindowLow})
	for _, h := range headers {
		state.Append(h)
	}
	state.RetainedWindow[0].Version = 3
	requireUnsupportedHeader(t, AuthorizeRetainedWindow(state, VerifyOptions{}))
}

func TestLoadOrInit_UnsupportedRetainedVersionBeforeTruncation(t *testing.T) {
	state := sampleState(t)
	state.RetainedWindow[0].Version = 3
	path := filepath.Join(t.TempDir(), "state.json")
	raw, err := json.Marshal(persistedState{
		Version: stateFileVersion, Genesis: state.Genesis,
		Window: state.RetainedWindow, Capacity: state.Capacity,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// A smaller window would discard the unsupported header if the
	// loader truncated before checking the complete stored window.
	_, err = LoadOrInit(path, state.Genesis, Policy{W: 0})
	if !errors.Is(err, chain.ErrUnsupportedHeaderVersion) {
		t.Fatalf("load error = %v, want unsupported header version", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, after) {
		t.Error("refused load modified the state file")
	}
}

func TestSaveHeaderState_UnsupportedVersionPreservesFile(t *testing.T) {
	state := sampleState(t)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := SaveHeaderState(path, state); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	state.RetainedWindow[0].Version = 3
	if err := SaveHeaderState(path, state); !errors.Is(err, chain.ErrUnsupportedHeaderVersion) {
		t.Fatalf("save error = %v, want unsupported header version", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("unsupported state replaced the existing file")
	}
}
