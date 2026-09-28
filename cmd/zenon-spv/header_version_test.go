package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/proof"
)

func TestVerifyHeadersCLI_UnsupportedVersionDoesNotPersist(t *testing.T) {
	bundlePath, genesisPath := stateValueBundleFromValidHeaders(t, nil)
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := proof.UnmarshalHeaderBundleJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	last := &bundle.Headers[len(bundle.Headers)-1]
	last.Version = 2
	last.HeaderHash = last.ComputeHash()
	last.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), last.HeaderHash[:])
	raw, err = proof.MarshalHeaderBundleJSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "state.json")
	code, out := captureRun(t, func() int {
		return runVerifyHeaders([]string{"--genesis-config", genesisPath, "--state", statePath, bundlePath})
	})
	if code != 2 || !strings.Contains(out, "REFUSED ReasonUnsupportedHeaderVersion") {
		t.Fatalf("exit=%d, output=%q; want unsupported-version refusal", code, out)
	}
	if strings.Contains(out, "ACCEPT") {
		t.Error("unsupported version reported ACCEPT")
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported bundle created a state file: %v", err)
	}
}
