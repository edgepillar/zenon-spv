package conformance_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

const accountPoWCorpusSHA256 = "560ff77f5fe092e99222399309da164c0539dec749e95b0e1788cd52fe30716f"
const originalAccountPoWProfile = "difficulty-0/nonce-0000000000000000"

func loadAccountPoWObservations(t *testing.T) []accountBasicObservation {
	t.Helper()
	raw, err := os.ReadFile("../testdata/conformance/node-account-pow.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != accountPoWCorpusSHA256 {
		t.Fatal("node account PoW observation bytes differ")
	}
	var corpus struct {
		Format int `json:"format_version"`
		Source struct {
			Commit    string   `json:"commit"`
			Functions []string `json:"functions"`
		} `json:"source"`
		Probes       []json.RawMessage         `json:"pow_probes"`
		Observations []accountBasicObservation `json:"observations"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Format != 1 || corpus.Source.Commit != "c64ed6279ff1d07335dab0ac36156dec8b5b71e9" ||
		len(corpus.Probes) != 32 || len(corpus.Observations) != 64 ||
		!slices.Equal(corpus.Source.Functions, []string{"pow.GetAccountBlockHash", "pow.CheckPoWNonce", "pow.GetThresholdByDifficulty",
			"common/crypto.Hash", "verifier.AccountBlockVerifier.AccountBlock", "verifier.AccountBlockVerifier.AccountBlockTransaction"}) {
		t.Fatal("unexpected selected account PoW observations")
	}
	// Select the complete difficulty/nonce/method order independently of the node
	// result. In particular, a matching nonce never selects an expected ACCEPT.
	index := 0
	for _, difficulty := range []uint64{0, 1, 2, 1000, 1<<63 - 1, 1 << 63, 1<<64 - 2, 1<<64 - 1} {
		for _, nonce := range []string{"0000000000000000", "0100000000000000", "0123456789abcdef", "ffffffffffffffff"} {
			for _, method := range []string{"AccountBlock", "AccountBlockTransaction"} {
				row := corpus.Observations[index]
				profile := fmt.Sprintf("difficulty-%d/nonce-%s", difficulty, nonce)
				if row.Profile != profile || row.Method != method || row.Name != "user-type-2/"+profile+"/"+method {
					t.Fatal("account PoW observation order differs from the selected inputs")
				}
				index++
			}
		}
	}
	return corpus.Observations
}

func accountPoWBlock(t *testing.T, row accountBasicObservation, original chain.AccountBlock) chain.AccountBlock {
	t.Helper()
	block := accountBasicBlock(t, row)
	if fmt.Sprintf("difficulty-%d/nonce-%s", block.Difficulty, hex.EncodeToString(block.Nonce[:])) != row.Profile {
		t.Fatal("wire scalar bytes differ from the independently selected PoW profile")
	}
	unchanged := block
	unchanged.Difficulty, unchanged.Nonce = original.Difficulty, original.Nonce
	if !reflect.DeepEqual(unchanged, original) || original.Difficulty != 0 || original.Nonce != (chain.Nonce{}) {
		t.Fatal("PoW projection changed another original signed input")
	}
	return block
}

func logAccountPoWBoundary(t *testing.T, phase string, cases, accepted, rejected, refused int) {
	t.Helper()
	if cases != accepted+rejected+refused {
		t.Fatal("account PoW boundary inventory does not add up")
	}
	raw, err := json.Marshal(map[string]any{
		"schema_version": 1, "phase": phase, "cases": cases, "accepted": accepted, "rejected": rejected, "refused": refused,
		"corpus_sha256": accountPoWCorpusSHA256, "node_revision": "c64ed6279ff1d07335dab0ac36156dec8b5b71e9",
		"runtime_acceptance_changed": false, "account_pow_qualified": false, "new_signatures_generated": false,
		"network_pilot_qualified": false, "state_value_acceptance": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("node-account-pow-boundary %s", raw)
}

func TestNodeAccountPoWRuntimeBoundaries(t *testing.T) {
	original := accountBasicRPCUser(t).Vectors[0].Block
	state, bundle := accountReceiveRPCState(t)
	before := state.Snapshot()
	accepted, rejected := 0, 0
	for _, row := range loadAccountPoWObservations(t) {
		t.Run(row.Name, func(t *testing.T) {
			block := accountPoWBlock(t, row, original)
			result := state.VerifySegment(proof.AccountSegment{Address: original.Address, Blocks: []chain.AccountBlock{block}}, bundle.Commitments)
			if row.Profile == originalAccountPoWProfile {
				assertReceiveRPCInclusion(t, result, 1)
				accepted++
			} else {
				if len(result.Blocks) != 1 || result.Worst() != verify.OutcomeReject ||
					result.Blocks[0].Reason != verify.ReasonInvalidHash || len(result.Blocks[0].Proven) != 0 {
					t.Fatal("node work or method outcome bypassed the original claimed hash")
				}
				rejected++
			}
			if !reflect.DeepEqual(before, state.Snapshot()) {
				t.Fatal("account PoW query changed selected verified state")
			}
		})
	}
	if accepted != 2 || rejected != 62 {
		t.Fatal("original account PoW runtime inventory differs")
	}
	logAccountPoWBoundary(t, "runtime-original", 64, accepted, rejected, 0)
}

func TestNodeAccountPoWRuntimeCoherentHash(t *testing.T) {
	original := accountBasicRPCUser(t).Vectors[0].Block
	state, bundle := accountReceiveRPCState(t)
	before := state.Snapshot()
	checked := 0
	for _, row := range loadAccountPoWObservations(t) {
		if row.Profile == originalAccountPoWProfile {
			continue
		}
		t.Run(row.Name, func(t *testing.T) {
			block := accountPoWBlock(t, row, original)
			block.BlockHash = block.ComputeHash()
			result := state.VerifySegment(proof.AccountSegment{Address: original.Address, Blocks: []chain.AccountBlock{block}}, bundle.Commitments)
			if len(result.Blocks) != 1 || result.Worst() != verify.OutcomeReject ||
				result.Blocks[0].Reason != verify.ReasonInvalidSignature || len(result.Blocks[0].Proven) != 0 ||
				!reflect.DeepEqual(before, state.Snapshot()) {
				t.Fatal("coherent changed hash or matching work bypassed the unchanged original signature")
			}
			checked++
		})
	}
	if checked != 62 {
		t.Fatal("coherent account PoW signature inventory differs")
	}
	logAccountPoWBoundary(t, "runtime-coherent-hash", checked, 0, checked, 0)
}
