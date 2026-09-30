package conformance_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestCompiledCLIBundleCountBounds(t *testing.T) {
	binary := buildQueryCLIs(t, "zenon-spv")["zenon-spv"]
	c, _ := contractBatchBundle(t)
	anchor := writeCLIJSON(t, t.TempDir(), "anchor.json", c.Chain.Anchor)
	for _, tc := range []struct {
		command, field, reason string
		limit                  int
	}{
		{"verify-headers", "headers", "ReasonOversizedHeaders", verify.DefaultMaxHeaders},
		{"verify-commitment", "commitments", "ReasonOversizedEvidence", verify.DefaultMaxCommitments},
		{"verify-segment", "segments", "ReasonOversizedSegment", verify.DefaultMaxSegments},
		{"verify-state-value", "state_value_proofs", "ReasonOversizedStateProof", verify.DefaultMaxStateValueProofs},
	} {
		t.Run(tc.command, func(t *testing.T) {
			dir := t.TempDir()
			state, bundle := filepath.Join(dir, "PRIVATE_STATE.json"), filepath.Join(dir, "PRIVATE_BUNDLE.json")
			if err := os.WriteFile(state, []byte("PRIVATE_STATE_NOT_LOADED"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(protectCLIState(t, state))
			raw := []byte(fmt.Sprintf(`{"version":1,"%s":[%s"PRIVATE_UNREACHED_ROW"]}`,
				tc.field, strings.Repeat("null,", tc.limit)))
			if err := os.WriteFile(bundle, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			result := runQueryCLI(t, binary, tc.command, "--json", "--genesis-config", anchor, "--state", state, bundle)
			r := checkProcessReport(t, result, 2, "REFUSED")
			if r.Error != nil || r.Persistence != "not_attempted" || r.Context != nil || r.Tip.Height != 0 || len(r.Results) != 1 || r.Results[0].Reference.Scope != "bundle" || r.Results[0].Reason != tc.reason || len(r.Results[0].Proven) != 0 {
				t.Fatal("count refusal reached verification or lost its resource reason")
			}
			if bytes.Contains(result.stdout, []byte("PRIVATE")) || bytes.Contains(result.stderr, []byte("PRIVATE")) {
				t.Fatal("count refusal disclosed a private path or excess row")
			}
			if _, err := os.Stat(state + ".lock"); !os.IsNotExist(err) {
				t.Fatal("early count refusal created a writer companion")
			}
		})
	}
}
