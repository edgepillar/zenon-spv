package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestBundleCountRefusesBeforeDecodingExcessRow(t *testing.T) {
	for _, tc := range []struct {
		field, reason string
		limit         int
	}{
		{"headers", "ReasonOversizedHeaders", verify.DefaultMaxHeaders},
		{"commitments", "ReasonOversizedEvidence", verify.DefaultMaxCommitments},
		{"segments", "ReasonOversizedSegment", verify.DefaultMaxSegments},
		{"state_value_proofs", "ReasonOversizedStateProof", verify.DefaultMaxStateValueProofs},
	} {
		t.Run(tc.field, func(t *testing.T) {
			dir := t.TempDir()
			path, statePath := filepath.Join(dir, "PRIVATE_BUNDLE.json"), filepath.Join(dir, "PRIVATE_STATE.json")
			raw := []byte(fmt.Sprintf(`{"version":1,"%s":[%s"PRIVATE_UNREACHED_ROW"]}`,
				tc.field, strings.Repeat("null,", tc.limit)))
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(statePath, []byte("PRIVATE_STATE_NOT_LOADED"), 0o600); err != nil {
				t.Fatal(err)
			}
			unchanged := unchangedQueryFile(t, statePath)
			defer unchanged(t)
			r := readVerificationReport(t, "verify-headers", []string{"--state", statePath, path}, 2)
			assertReportOutcome(t, r, "REFUSED")
			if len(r.Results) != 1 || r.Results[0].Reason != tc.reason || r.Results[0].Reference.Scope != "bundle" || len(r.Results[0].Proven) != 0 || r.Error != nil || r.Persistence != "not_attempted" || r.Context != nil || r.VerificationTip != nil || len(r.StateTrust) != 0 {
				t.Fatal("excess rows bypassed the count refusal or reached state verification")
			}
			encoded, err := json.Marshal(r)
			if err != nil || bytes.Contains(encoded, []byte("PRIVATE")) {
				t.Fatal("count refusal disclosed a private input")
			}
			if _, err := os.Stat(statePath + ".lock"); !os.IsNotExist(err) {
				t.Fatal("count refusal acquired a writer companion")
			}
		})
	}
}

func TestNestedBundleCountRefusesBeforeDecodingExcessRow(t *testing.T) {
	for _, tc := range []struct {
		name, command, envelope, reason string
		limit                           int
	}{
		{"blocks", "verify-segment", `{"version":1,"segments":[{"blocks":[%s"PRIVATE_UNREACHED_ROW"]}]}`, "ReasonOversizedSegment", verify.DefaultMaxSegmentBlocks},
		{"flat members", "verify-commitment", `{"version":1,"commitments":[{"flat":{"sorted_headers":[%s"PRIVATE_UNREACHED_ROW"]}}]}`, "ReasonOversizedEvidence", verify.DefaultMaxFlatEvidenceMembers},
		{"proof nodes", "verify-state-value", `{"version":1,"state_value_proofs":[{"proof_nodes":[%s"PRIVATE_UNREACHED_ROW"]}]}`, "ReasonOversizedStateProof", verify.DefaultMaxStateProofNodes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "PRIVATE_BUNDLE.json")
			raw := []byte(fmt.Sprintf(tc.envelope, strings.Repeat("null,", tc.limit)))
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			r := readVerificationReport(t, tc.command, []string{path}, 2)
			assertReportOutcome(t, r, "REFUSED")
			if len(r.Results) != 1 || r.Results[0].Reason != tc.reason || r.Error != nil {
				t.Fatal("excess nested rows were decoded before the count refusal")
			}
		})
	}
}
