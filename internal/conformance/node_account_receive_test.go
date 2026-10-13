package conformance_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func loadAccountReceiveObservations(t *testing.T) []accountBasicObservation {
	t.Helper()
	raw, err := os.ReadFile("../testdata/conformance/node-account-receive.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "153c7563d863ccfb1563a1bdaca310215a415236ef0bf9e85c2e44228a1fe21c" {
		t.Fatal("node account receive observation bytes differ")
	}
	var corpus struct {
		Format int `json:"format_version"`
		Source struct {
			Commit      string   `json:"commit"`
			Methods     []string `json:"methods"`
			Enforcement uint64   `json:"receiver_mismatch_enforcement_height"`
		} `json:"source"`
		Observations []accountBasicObservation `json:"observations"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Format != 1 || corpus.Source.Commit != "c64ed6279ff1d07335dab0ac36156dec8b5b71e9" ||
		corpus.Source.Enforcement != 10109240 || len(corpus.Observations) != 44 ||
		!slices.Equal(corpus.Source.Methods, []string{"verifier.AccountBlockVerifier.AccountBlock", "verifier.AccountBlockVerifier.AccountBlockTransaction"}) {
		t.Fatal("unexpected selected receive observations")
	}
	return corpus.Observations
}

func TestNodeAccountReceiveRuntimeBoundaries(t *testing.T) {
	// Select the original signed history and commitments before any observation.
	// The receive store, its confirmation/received records and node outcomes are
	// not trust inputs to inclusion or evidence of account execution eligibility.
	anchor, bundle := nodeAccountBundle(t)
	initial, err := verify.NewVerifiedState(anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	r, state := initial.Extend(bundle.Headers)
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	before := state.Snapshot()
	counts := make(map[verify.Outcome]int)
	for _, row := range loadAccountReceiveObservations(t) {
		t.Run(row.Name, func(t *testing.T) {
			block := accountBasicBlock(t, row)
			if block.BlockType != chain.BlockTypeUserReceive || block.Height != 2 {
				t.Fatal("unselected receive projection")
			}
			want := verify.OutcomeAccept
			if strings.HasPrefix(row.Profile, "receive-") {
				want = verify.OutcomeReject
			}
			result := state.VerifySegment(proof.AccountSegment{Address: block.Address, Blocks: []chain.AccountBlock{block}}, bundle.Commitments)
			if len(result.Blocks) != 1 || result.Worst() != want || !reflect.DeepEqual(before, state.Snapshot()) {
				t.Fatalf("node %s=%s/%s; SPV=%v; want=%s", row.Method, row.NodeResult, row.NodeError, result.Blocks, want)
			}
			got := result.Blocks[0]
			if want == verify.OutcomeAccept {
				if !slices.Contains(got.Proven, verify.GuaranteeContentInclusion) || !slices.Contains(got.Proven, verify.GuaranteeSignatureAuthenticity) ||
					!slices.Contains(got.NotProven, verify.GuaranteeStateTransition) {
					t.Fatal("missing bounded inclusion/signature scope or unproven execution")
				}
				assertBoundedGuarantees(t, got)
			} else if got.Reason != verify.ReasonInvalidHash {
				t.Fatal("changed receive bytes bypassed original hash binding")
			}
			counts[got.Outcome]++
		})
	}
	if counts[verify.OutcomeAccept] != 36 || counts[verify.OutcomeReject] != 8 || counts[verify.OutcomeRefused] != 0 {
		t.Fatalf("receive runtime inventory differs: %v", counts)
	}
}

func TestNodeAccountReceiveMatchCannotSupplyCommitmentInputs(t *testing.T) {
	anchor, bundle := nodeAccountBundle(t)
	initial, err := verify.NewVerifiedState(anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	r, retained := initial.Extend(bundle.Headers)
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	selected := 0
	for _, row := range loadAccountReceiveObservations(t) {
		if row.Profile != "exact" {
			continue
		}
		selected++
		t.Run(row.Name, func(t *testing.T) {
			if row.NodeResult != "MATCH" {
				t.Fatal("missing selected positive receive result")
			}
			block := accountBasicBlock(t, row)
			for _, tc := range []struct {
				name        string
				state       verify.VerifiedState
				commitments []proof.CommitmentEvidence
				reason      verify.ReasonCode
			}{{"header-not-retained", initial, bundle.Commitments, verify.ReasonHeightOutOfWindow},
				{"proof-not-supplied", retained, nil, verify.ReasonMissingProof}} {
				t.Run(tc.name, func(t *testing.T) {
					before := tc.state.Snapshot()
					result := tc.state.VerifySegment(proof.AccountSegment{Address: block.Address, Blocks: []chain.AccountBlock{block}}, tc.commitments)
					if len(result.Blocks) != 1 || result.Worst() != verify.OutcomeRefused || result.Blocks[0].Reason != tc.reason ||
						!reflect.DeepEqual(before, tc.state.Snapshot()) {
						t.Fatal("receive method or ledger records supplied missing commitment inputs")
					}
				})
			}
		})
	}
	if selected != 2 {
		t.Fatal("both receive entry points must be checked")
	}
}
