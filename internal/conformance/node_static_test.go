package conformance_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type staticNodeObservation struct {
	Name         string        `json:"name"`
	Baseline     string        `json:"baseline"`
	Header       *chain.Header `json:"header"`
	ComputedHash *chain.Hash   `json:"computed_hash"`
	NodeResult   string        `json:"node_static_result"`
	NodeError    string        `json:"node_error"`
}

func loadStaticNodeObservations(t *testing.T) []staticNodeObservation {
	t.Helper()
	raw, err := os.ReadFile("../testdata/conformance/node-static-v1-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "1873c677ea64936cea90262dbe70a5a76e497a8c6d7736394dd4eaee7da766c3" {
		t.Fatal("static node observation bytes differ")
	}
	var corpus struct {
		FormatVersion int `json:"format_version"`
		Source        struct {
			Commit   string `json:"commit"`
			Function string `json:"function"`
		} `json:"source"`
		Observations []staticNodeObservation `json:"observations"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.FormatVersion != 1 || corpus.Source.Commit != "c64ed6279ff1d07335dab0ac36156dec8b5b71e9" ||
		corpus.Source.Function != "verifier.MomentumStatic" || len(corpus.Observations) != 55 {
		t.Fatal("unexpected static node observation selection")
	}
	return corpus.Observations
}

func staticBaselineSelection(h chain.Header) (verify.GenesisTrustRoot, verify.Policy) {
	// Select trust only from the preserved original fixture, before mutations.
	// These synthetic anchors and profiles do not authenticate any network.
	anchor := verify.GenesisTrustRoot{ChainID: h.ChainIdentifier, Height: h.Height - 1, HeaderHash: h.PreviousHash}
	policy := verify.Policy{W: 1, RetainHeaders: 16}
	if h.Version == 2 {
		policy.ProtocolProfile = &verify.ProtocolProfile{Version: 1, Anchor: anchor,
			ValidThrough: h.Height + 1, V2FromHeight: h.Height, Source: "synthetic static-node conformance selection"}
	}
	return anchor, policy
}

func TestNodeStaticObservationsPreserveRuntimeBoundaries(t *testing.T) {
	original := loadCorpus(t)
	baselines := make(map[string]chain.Header)
	for _, v := range slices.Concat(original.Vectors, original.Chain.Vectors, original.Transition.Vectors) {
		baselines[v.Name] = v.Header
	}
	rawGenesis, err := os.ReadFile("../testdata/conformance/historical-testnet-genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	var genesis struct {
		Anchor verify.GenesisTrustRoot `json:"anchor"`
	}
	if err := json.Unmarshal(rawGenesis, &genesis); err != nil {
		t.Fatal(err)
	}
	counts := make(map[verify.Outcome]int)
	for _, row := range loadStaticNodeObservations(t) {
		t.Run(row.Name, func(t *testing.T) {
			anchor, policy := original.Chain.Anchor, verify.Policy{W: 1, RetainHeaders: 16}
			want := verify.OutcomeReject
			if row.NodeResult == "MATCH" {
				want = verify.OutcomeAccept
			}
			var headers []chain.Header
			if row.Header != nil {
				if row.ComputedHash == nil || row.Header.ComputeHash() != *row.ComputedHash {
					t.Fatal("runtime hash differs from the independent node observation")
				}
				headers = []chain.Header{*row.Header}
				if row.Name == "historical-unsigned-genesis" {
					// Genesis remains the selected anchor, never an ordinary extension.
					anchor = genesis.Anchor
				} else {
					base, ok := baselines[row.Baseline]
					if !ok {
						t.Fatal("unknown preserved baseline")
					}
					anchor, policy = staticBaselineSelection(base)
				}
			}
			switch row.Name {
			case "nil", "v2-nonzero-prices/chain":
				want = verify.OutcomeRefused
			case "baseline/v1-price-fields-not-hashed", "baseline/v2-zero-prices", "v1-empty/prices":
				want = verify.OutcomeReject
			}
			state := verify.NewHeaderState(anchor, policy)
			before, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			result, next := verify.VerifyHeaders(headers, state, policy)
			if result.Outcome != want {
				t.Fatalf("node primitive=%s/%s, runtime=%s/%s, want=%s", row.NodeResult, row.NodeError, result.Outcome, result.Reason, want)
			}
			switch row.Name {
			case "baseline/v1-price-fields-not-hashed", "baseline/v2-zero-prices", "v1-empty/prices":
				if row.NodeResult != "MATCH" || result.Reason != verify.ReasonInvalidResourcePrice {
					t.Fatal("static hash/signature match bypassed the runtime resource-price rule")
				}
			}
			if row.Name == "v1-empty/both-empty" || row.Name == "v2-nonzero-prices/both-empty" {
				if row.NodeError != "signature_missing" || result.Reason != verify.ReasonPublicKeyMissing {
					t.Fatal("node and runtime diagnostic precedence was conflated")
				}
			}
			after, err := json.Marshal(state)
			if err != nil || string(before) != string(after) {
				t.Fatal("verification changed the caller's selected state")
			}
			if want != verify.OutcomeAccept && !reflect.DeepEqual(next, state) {
				t.Fatal("rejection or refusal advanced state")
			}
			if want == verify.OutcomeAccept {
				assertBoundedGuarantees(t, result)
			}
			counts[result.Outcome]++
		})
	}
	if counts[verify.OutcomeAccept] != 19 || counts[verify.OutcomeReject] != 34 || counts[verify.OutcomeRefused] != 2 {
		t.Fatalf("runtime boundary inventory differs: %v", counts)
	}
}

func TestNodeStaticMatchCannotSupplyActivationOrProducerInputs(t *testing.T) {
	for _, row := range loadStaticNodeObservations(t) {
		if row.Name != "baseline/v1-empty" && row.Name != "baseline/v2-nonzero-prices" {
			continue
		}
		t.Run(row.Name, func(t *testing.T) {
			if row.NodeResult != "MATCH" {
				t.Fatal("selected positive node primitive is missing")
			}
			h := *row.Header
			anchor, policy := staticBaselineSelection(h)
			state := verify.NewHeaderState(anchor, policy)
			result, next := verify.VerifyHeadersWithOptions([]chain.Header{h}, state, verify.VerifyOptions{
				Policy: policy, ProducerAuth: verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired},
			})
			if result.Outcome != verify.OutcomeRefused || result.Reason != verify.ReasonProducerSetUnknown || !reflect.DeepEqual(next, state) {
				t.Fatal("static node result supplied missing producer authority")
			}
			if h.Version == 2 {
				policy.ProtocolProfile = nil
				state = verify.NewHeaderState(anchor, policy)
				result, next = verify.VerifyHeaders([]chain.Header{h}, state, policy)
				if result.Outcome != verify.OutcomeRefused || result.Reason != verify.ReasonProtocolProfileRequired || !reflect.DeepEqual(next, state) {
					t.Fatal("static node result supplied missing activation inputs")
				}
			}
		})
	}
}
