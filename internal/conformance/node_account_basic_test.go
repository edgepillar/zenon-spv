package conformance_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type accountBasicObservation struct {
	Name         string          `json:"name"`
	Profile      string          `json:"profile"`
	Method       string          `json:"method"`
	Wire         json.RawMessage `json:"account_block"`
	ComputedHash chain.Hash      `json:"computed_hash"`
	NodeResult   string          `json:"node_method_result"`
	NodeError    string          `json:"node_error"`
}

func loadAccountBasicObservations(t *testing.T) []accountBasicObservation {
	t.Helper()
	raw, err := os.ReadFile("../testdata/conformance/node-account-basic.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "133735fd68c2631bfd58071053333bd4a99786b4b83dd065005f41228fcdb204" {
		t.Fatal("node account basic observation bytes differ")
	}
	var corpus struct {
		Format int `json:"format_version"`
		Source struct {
			Commit  string   `json:"commit"`
			Methods []string `json:"methods"`
		} `json:"source"`
		Observations []accountBasicObservation `json:"observations"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Format != 1 || corpus.Source.Commit != "c64ed6279ff1d07335dab0ac36156dec8b5b71e9" ||
		!slices.Equal(corpus.Source.Methods, []string{"verifier.AccountBlockVerifier.AccountBlock", "verifier.AccountBlockVerifier.AccountBlockTransaction"}) ||
		len(corpus.Observations) != 50 {
		t.Fatal("unexpected selected basic method observations")
	}
	return corpus.Observations
}

func accountBasicBlock(t *testing.T, row accountBasicObservation) chain.AccountBlock {
	t.Helper()
	// Project only this pinned, no-descendant corpus into the lower-level API.
	// The independent Python checker validates the complete RPC/protobuf bytes.
	// This projection does not qualify acceptance by the production RPC decoder.
	var wire struct {
		chain.AccountBlock
		Amount        string            `json:"amount"`
		Address       string            `json:"address"`
		ToAddress     string            `json:"toAddress"`
		TokenStandard string            `json:"tokenStandard"`
		Data          []byte            `json:"data"`
		Descendants   []json.RawMessage `json:"descendantBlocks"`
	}
	if err := json.Unmarshal(row.Wire, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Descendants) != 0 {
		t.Fatal("unselected descendant layout")
	}
	b := wire.AccountBlock
	var ok bool
	if b.Amount, ok = new(big.Int).SetString(wire.Amount, 10); !ok {
		t.Fatal("unselected amount representation")
	}
	address, err := fetch.DecodeZenonAddress(wire.Address)
	if err != nil {
		t.Fatal(err)
	}
	b.Address = chain.Address(address)
	to, err := fetch.DecodeZenonAddress(wire.ToAddress)
	if err != nil {
		t.Fatal(err)
	}
	b.ToAddress = chain.Address(to)
	// These are the only two token encodings in the independently checked corpus.
	// Select their bytes from the original input, never from a node MATCH result.
	c := loadNodeAccountCorpus(t, "account-segments.json")
	var originalToken string
	var originalBytes chain.TokenStandard
	for _, segment := range c.Segments {
		for _, v := range segment.Vectors {
			if v.Name == "user-type-2" {
				var original struct {
					Token string `json:"tokenStandard"`
				}
				if err := json.Unmarshal(v.RPC, &original); err != nil {
					t.Fatal(err)
				}
				originalToken, originalBytes = original.Token, v.Block.TokenStandard
			}
		}
	}
	if originalToken == "" {
		t.Fatal("missing original token selection")
	}
	switch wire.TokenStandard {
	case originalToken:
		b.TokenStandard = originalBytes
	case "zts1qqqqqqqqqqqqqqqqtq587y":
		b.TokenStandard = chain.TokenStandard{}
	default:
		t.Fatal("unselected token encoding")
	}
	b.DataHash = chain.Hash(sha3.Sum256(wire.Data))
	b.DescendantBlocksHash = chain.Hash(sha3.Sum256(nil))
	if b.ComputeHash() != row.ComputedHash {
		t.Fatal("SPV projection differs from node and independent hash bytes")
	}
	return b
}

func TestNodeAccountBasicRuntimeBoundaries(t *testing.T) {
	// All trust/commitment inputs come from the original signed fixture.
	// The observation's caller-selected stores and unsigned records supply none.
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
	for _, row := range loadAccountBasicObservations(t) {
		t.Run(row.Name, func(t *testing.T) {
			block := accountBasicBlock(t, row)
			want := verify.OutcomeReject
			switch row.Profile {
			case "first-exact-ack", "stored-chain-mismatch", "ack-missing", "ack-wrong-hash", "ack-corrupt-entry":
				want = verify.OutcomeAccept
			case "version-zero", "version-two", "type-zero", "type-genesis", "type-unsupported":
				want = verify.OutcomeRefused
			}
			result := state.VerifySegment(proof.AccountSegment{Address: block.Address, Blocks: []chain.AccountBlock{block}}, bundle.Commitments)
			if len(result.Blocks) != 1 || result.Worst() != want {
				t.Fatalf("node %s=%s/%s; SPV=%v; want=%s", row.Method, row.NodeResult, row.NodeError, result.Blocks, want)
			}
			got := result.Blocks[0]
			if !reflect.DeepEqual(before, state.Snapshot()) {
				t.Fatal("query changed selected verified state")
			}
			if want == verify.OutcomeAccept {
				if !slices.Contains(got.Proven, verify.GuaranteeContentInclusion) || !slices.Contains(got.Proven, verify.GuaranteeSignatureAuthenticity) {
					t.Fatal("missing independently selected commitment or signature guarantee")
				}
				assertBoundedGuarantees(t, got)
			}
			switch row.Profile {
			case "amount-negative", "amount-large":
				if got.Reason != verify.ReasonInvalidAmount {
					t.Fatal("node method outcome bypassed scalar validation")
				}
			case "hash-zero", "hash-mutated":
				if got.Reason != verify.ReasonInvalidHash || (row.Method == "AccountBlock" && row.NodeResult != "MATCH") {
					t.Fatal("basic method match bypassed cryptographic validation")
				}
			case "signature-empty":
				if got.Reason != verify.ReasonSignatureMissing || (row.Method == "AccountBlock" && row.NodeResult != "MATCH") {
					t.Fatal("basic method match bypassed signature validation")
				}
			}
			counts[got.Outcome]++
		})
	}
	if counts[verify.OutcomeAccept] != 10 || counts[verify.OutcomeReject] != 30 || counts[verify.OutcomeRefused] != 10 {
		t.Fatalf("runtime boundary inventory differs: %v", counts)
	}
}

func TestNodeAccountBasicMatchCannotSupplyCommitmentInputs(t *testing.T) {
	anchor, bundle := nodeAccountBundle(t)
	state, err := verify.NewVerifiedState(anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	r, retained := state.Extend(bundle.Headers)
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	cases := []struct {
		name        string
		state       verify.VerifiedState
		commitments []proof.CommitmentEvidence
		reason      verify.ReasonCode
	}{
		{"header-not-retained", state, bundle.Commitments, verify.ReasonHeightOutOfWindow},
		{"proof-not-supplied", retained, nil, verify.ReasonMissingProof},
	}
	selected := 0
	for _, row := range loadAccountBasicObservations(t) {
		if row.Profile != "first-exact-ack" {
			continue
		}
		selected++
		t.Run(row.Name, func(t *testing.T) {
			if row.NodeResult != "MATCH" {
				t.Fatal("selected positive method result missing")
			}
			block := accountBasicBlock(t, row)
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					before := tc.state.Snapshot()
					result := tc.state.VerifySegment(proof.AccountSegment{Address: block.Address, Blocks: []chain.AccountBlock{block}}, tc.commitments)
					if len(result.Blocks) != 1 || result.Worst() != verify.OutcomeRefused || result.Blocks[0].Reason != tc.reason ||
						!reflect.DeepEqual(before, tc.state.Snapshot()) {
						t.Fatal("real memory stores or node match supplied missing commitment inputs")
					}
				})
			}
		})
	}
	if selected != 2 {
		t.Fatal("both node entry points must be checked")
	}
}
