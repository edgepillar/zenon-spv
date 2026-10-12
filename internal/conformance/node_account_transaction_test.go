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

type accountTransactionObservation struct {
	Name         string              `json:"name"`
	Baseline     string              `json:"baseline"`
	Block        *chain.AccountBlock `json:"block"`
	ComputedHash *chain.Hash         `json:"computed_hash"`
	NodeResult   string              `json:"node_transaction_result"`
	NodeError    string              `json:"node_error"`
}

func loadAccountTransactionObservations(t *testing.T) []accountTransactionObservation {
	t.Helper()
	raw, err := os.ReadFile("../testdata/conformance/node-account-transactions.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "8f3858bf3cb0d77ded8ae4d12b500a3d21c54492f1f5f4dc5014da531f23df32" {
		t.Fatal("node account transaction observation bytes differ")
	}
	var corpus struct {
		Format       int                               `json:"format_version"`
		Source       struct{ Commit, Function string } `json:"source"`
		Observations []accountTransactionObservation   `json:"observations"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Format != 1 || corpus.Source.Commit != "c64ed6279ff1d07335dab0ac36156dec8b5b71e9" ||
		corpus.Source.Function != "verifier.AccountBlockVerifier.AccountBlockTransaction" || len(corpus.Observations) != 58 {
		t.Fatal("unexpected selected method observations")
	}
	return corpus.Observations
}

func TestNodeAccountTransactionRuntimeBoundaries(t *testing.T) {
	// Trust inputs and commitments come only from the original signed chain,
	// before any node method mutation. Opaque node stubs supply no trust here.
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
	for _, row := range loadAccountTransactionObservations(t) {
		t.Run(row.Name, func(t *testing.T) {
			want := verify.OutcomeReject
			var segment proof.AccountSegment
			if row.Block != nil {
				if row.ComputedHash == nil || row.Block.ComputeHash() != *row.ComputedHash {
					t.Fatal("SPV hash differs from node and independent bytes")
				}
				segment = proof.AccountSegment{Address: row.Block.Address, Blocks: []chain.AccountBlock{*row.Block}}
			} else {
				if row.NodeResult != "PANIC" || row.NodeError != "nil_pointer" {
					t.Fatal("unselected nil observation")
				}
				want = verify.OutcomeRefused
			}
			switch row.Name {
			case "baseline/user-type-2", "baseline/user-type-3", "baseline/embedded-type-5", "baseline/embedded-type-4",
				"user-type-2/changes-hash-bit", "user-type-2/base-plasma-one", "user-type-2/used-plasma-one", "user-type-3/amount-nil":
				want = verify.OutcomeAccept
			case "baseline/zero", "baseline/ordinary", "baseline/max-255-bits",
				"embedded-type-5/version-zero", "embedded-type-5/version-two", "embedded-type-5/type-zero", "embedded-type-5/type-six",
				"embedded-type-5/receive-amount-one", "embedded-type-5/receive-token-nonzero", "embedded-type-5/receive-to-nonzero",
				"embedded-type-5/receive-from-zero", "embedded-type-5/difficulty-one", "embedded-type-5/fused-plasma-one":
				want = verify.OutcomeRefused
			}
			result := state.VerifySegment(segment, bundle.Commitments)
			if len(result.Blocks) != 1 || result.Worst() != want {
				t.Fatalf("node method=%s/%s; SPV=%v; want=%s", row.NodeResult, row.NodeError, result.Blocks, want)
			}
			if !reflect.DeepEqual(before, state.Snapshot()) {
				t.Fatal("query changed selected verified state")
			}
			got := result.Blocks[0]
			if want == verify.OutcomeAccept {
				if !slices.Contains(got.Proven, verify.GuaranteeContentInclusion) {
					t.Fatal("missing commitment guarantee")
				}
				if slices.Contains(got.Proven, verify.GuaranteeSignatureAuthenticity) == segment.Address.IsEmbeddedAddress() {
					t.Fatal("wrong user or embedded signature guarantee")
				}
				assertBoundedGuarantees(t, got)
			}
			if row.Name == "user-type-2/amount-negative" {
				if row.NodeResult != "MATCH" || got.Reason != verify.ReasonInvalidAmount {
					t.Fatal("transaction method match bypassed scalar validation")
				}
			}
			if row.Name == "user-type-3/amount-nil" && row.NodeResult != "MATCH" {
				t.Fatal("programmatic nil zero representation changed")
			}
			if strings.HasPrefix(row.Name, "embedded-type-5/") && got.Reason == verify.ReasonMissingProof {
				if row.NodeResult != "MATCH" || want != verify.OutcomeRefused {
					t.Fatal("coherent claim acquired commitment")
				}
			}
			if row.Name == "baseline/embedded-type-4" && row.NodeError != "external_batched_type" {
				t.Fatal("standalone node transaction and committed embedded send paths conflated")
			}
			if row.Name == "user-type-2/both-empty" &&
				(row.NodeError != "signature_missing" || got.Reason != verify.ReasonPublicKeyMissing) {
				t.Fatal("node and SPV diagnostic precedence conflated")
			}
			counts[got.Outcome]++
		})
	}
	if counts[verify.OutcomeAccept] != 8 || counts[verify.OutcomeReject] != 35 || counts[verify.OutcomeRefused] != 15 {
		t.Fatalf("runtime boundary inventory differs: %v", counts)
	}
}

func TestNodeAccountTransactionMatchCannotSupplyCommitments(t *testing.T) {
	anchor, bundle := nodeAccountBundle(t)
	state, err := verify.NewVerifiedState(anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range loadAccountTransactionObservations(t) {
		if row.Name != "baseline/user-type-2" && row.Name != "baseline/embedded-type-5" {
			continue
		}
		t.Run(row.Name, func(t *testing.T) {
			if row.NodeResult != "MATCH" {
				t.Fatal("selected positive method result missing")
			}
			segment := proof.AccountSegment{Address: row.Block.Address, Blocks: []chain.AccountBlock{*row.Block}}
			result := state.VerifySegment(segment, bundle.Commitments)
			if result.Worst() != verify.OutcomeRefused || result.Blocks[0].Reason != verify.ReasonHeightOutOfWindow || !state.Empty() {
				t.Fatal("node transaction match supplied retained committing momentum")
			}
		})
	}
}
