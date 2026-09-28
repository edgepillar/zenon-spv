package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func signedRetainedState(t *testing.T, n int, window uint64) HeaderState {
	t.Helper()
	anchor, headers, _ := buildChain(t, n)
	state := NewHeaderState(anchor, Policy{W: window})
	for _, header := range headers {
		state.Append(header)
	}
	return state
}

func writeUncheckedState(t *testing.T, path string, state HeaderState) []byte {
	t.Helper()
	raw, err := json.Marshal(persistedState{Version: stateFileVersion, Genesis: state.Genesis,
		Window: state.RetainedWindow, Capacity: state.Capacity})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLoadOrInit_ValidatesRetainedStateBeforeTruncation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*HeaderState)
	}{
		{"first-hash", func(s *HeaderState) { s.RetainedWindow[0].HeaderHash[0] ^= 1 }},
		{"middle-signature", func(s *HeaderState) { s.RetainedWindow[2].Signature[0] ^= 1 }},
		{"tip-data", func(s *HeaderState) { s.RetainedWindow[5].DataHash[0] ^= 1 }},
		{"missing-key", func(s *HeaderState) { s.RetainedWindow[1].PublicKey = nil }},
		{"wrong-network", func(s *HeaderState) { s.RetainedWindow[0].ChainIdentifier++ }},
		{"broken-link", func(s *HeaderState) { s.RetainedWindow[3].PreviousHash[0] ^= 1 }},
		{"height-gap", func(s *HeaderState) { s.RetainedWindow[2].Height++ }},
		{"duplicate-height", func(s *HeaderState) { s.RetainedWindow[2] = s.RetainedWindow[1] }},
		{"anchor-link", func(s *HeaderState) { s.Genesis.HeaderHash[0] ^= 1 }},
		{"anchor-height", func(s *HeaderState) { s.Genesis.Height = s.RetainedWindow[0].Height }},
		{"zero-capacity", func(s *HeaderState) { s.Capacity = 0 }},
		{"negative-capacity", func(s *HeaderState) { s.Capacity = -1 }},
		{"undersized-capacity", func(s *HeaderState) { s.Capacity = 1 }},
		{"excessive-capacity", func(s *HeaderState) { s.Capacity = DefaultMaxHeaders + 2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := signedRetainedState(t, 6, 6)
			tc.edit(&state)
			path := filepath.Join(t.TempDir(), "state.json")
			raw := writeUncheckedState(t, path, state)
			if _, err := LoadOrInit(path, state.Genesis, Policy{W: 0}); err == nil {
				t.Fatal("invalid retained state accepted after truncating to one header")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, after) {
				t.Fatal("failed load modified the state file")
			}
		})
	}
}

func TestSaveHeaderState_InvalidStatePreservesFile(t *testing.T) {
	state := signedRetainedState(t, 6, 6)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := SaveHeaderState(path, state); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	state.RetainedWindow[0].Signature[0] ^= 1
	if err := SaveHeaderState(path, state); err == nil {
		t.Fatal("invalid signature overwrote valid persisted state")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid state replaced the existing file")
	}
}

func TestLoadHeaderState_EvictedPrefixRemainsUsable(t *testing.T) {
	state := signedRetainedState(t, 9, 2)
	if state.RetainedWindow[0].Height == state.Genesis.Height+1 {
		t.Fatal("fixture must have evicted its prefix")
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := SaveHeaderState(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadHeaderState(path)
	if err != nil {
		t.Fatal(err)
	}
	if tip, ok := loaded.Tip(); !ok || tip.HeaderHash == (chain.Hash{}) || tip.HeaderHash != state.RetainedWindow[2].HeaderHash {
		t.Fatal("valid truncated window did not survive validation")
	}
}

func TestStateFileByteBounds(t *testing.T) {
	state := signedRetainedState(t, 3, 6)
	path := filepath.Join(t.TempDir(), "state.json")
	raw := writeUncheckedState(t, path, state)
	if _, err := decodeHeaderState(bytes.NewReader(raw), int64(len(raw))); err != nil {
		t.Fatalf("exact byte boundary: %v", err)
	}
	padded := bytes.NewReader(append(raw, make([]byte, 1024)...))
	if _, err := decodeHeaderState(padded, int64(len(raw))); !errors.Is(err, ErrStateFileTooLarge) {
		t.Fatalf("bounded reader: %v", err)
	}
	if padded.Len() != 1023 {
		t.Fatalf("reader consumed beyond its one-byte overflow probe: remaining=%d", padded.Len())
	}
	if err := os.Truncate(path, MaxStateFileBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHeaderState(path); !errors.Is(err, ErrStateFileTooLarge) {
		t.Fatalf("oversized file: %v", err)
	}
	var out bytes.Buffer
	w := limitedStateWriter{destination: &out, remaining: 3}
	if n, err := w.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatalf("writer exact boundary: n=%d err=%v", n, err)
	}
	if n, err := w.Write([]byte("d")); n != 0 || !errors.Is(err, ErrStateFileTooLarge) || out.String() != "abc" {
		t.Fatalf("writer exceeded bound: n=%d err=%v", n, err)
	}
}

func TestLoadOrInit_RejectsExcessiveWindowBeforeAllocation(t *testing.T) {
	state := signedRetainedState(t, 3, 6)
	for _, window := range []uint64{uint64(MaxPersistedHeaders), ^uint64(0)} {
		if _, err := LoadOrInit(filepath.Join(t.TempDir(), "absent.json"), state.Genesis, Policy{W: window}); !errors.Is(err, ErrInvalidRetainedState) {
			t.Fatalf("window=%d: %v", window, err)
		}
	}
}

func TestLoadHeaderState_RechecksEmbeddedCheckpoint(t *testing.T) {
	state := signedRetainedState(t, 1, 1)
	cp := MainnetCheckpoints()[0]
	state.Genesis.ChainID, state.Genesis.Height = MainnetChainID, cp.Height-1
	h := &state.RetainedWindow[0]
	h.ChainIdentifier, h.Height = MainnetChainID, cp.Height
	h.HeaderHash = h.ComputeHash()
	h.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(fixtureSeed), h.HeaderHash[:])
	path := filepath.Join(t.TempDir(), "state.json")
	writeUncheckedState(t, path, state)
	if _, err := LoadHeaderState(path); !errors.Is(err, ErrInvalidRetainedState) || !strings.Contains(err.Error(), "checkpoint mismatch") {
		t.Fatalf("self-consistent wrong checkpoint accepted: %v", err)
	}
}
