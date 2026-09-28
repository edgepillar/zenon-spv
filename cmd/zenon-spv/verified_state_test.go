package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestVerifyHeadersCLI_ReportsTrustedResumeSeparately(t *testing.T) {
	bundlePath, genesisPath := stateValueBundleFromLongChain(t, 12, nil)
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := proof.UnmarshalHeaderBundleJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	all := bundle.Headers
	statePath := filepath.Join(t.TempDir(), "state.json")
	for batch := range 2 {
		bundle.Headers = all[batch*6 : (batch+1)*6]
		encoded, err := proof.MarshalHeaderBundleJSON(bundle)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bundlePath, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		code, output := captureRun(t, func() int {
			return runVerifyHeaders([]string{"--genesis-config", genesisPath, "--state", statePath, bundlePath})
		})
		if code != 0 || !strings.Contains(output, string(verify.TrustConfiguredAnchor)) {
			t.Fatalf("batch %d: exit=%d output=%s", batch, code, output)
		}
		if got := strings.Contains(output, string(verify.TrustPersistedState)); got != (batch == 1) {
			t.Fatalf("batch %d: persisted-state trust=%v", batch, got)
		}
	}
}
