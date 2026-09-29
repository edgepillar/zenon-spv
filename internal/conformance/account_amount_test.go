package conformance_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestNodeDerivedAccountAmountVectors(t *testing.T) {
	raw, err := os.ReadFile("../testdata/conformance/account-amounts.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		FormatVersion int `json:"format_version"`
		Source        struct {
			Commit string `json:"commit"`
		} `json:"source"`
		Vectors []struct {
			Name        string             `json:"name"`
			ScalarValid bool               `json:"scalar_valid"`
			RPC         json.RawMessage    `json:"rpc"`
			Block       chain.AccountBlock `json:"block"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.FormatVersion != 1 || corpus.Source.Commit != "3a4131e63881058b6ce2ee81d3a41d0033fafc99" || len(corpus.Vectors) != 7 {
		t.Fatal("unexpected account amount corpus")
	}
	for _, v := range corpus.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.Block.ComputeHash() != v.Block.BlockHash {
				t.Fatal("SPV hash differs from pinned node serialization")
			}
			if !ed25519.Verify(v.Block.PublicKey, v.Block.BlockHash[:], v.Block.Signature) {
				t.Fatal("invalid synthetic node-vector signature")
			}
			if (chain.ValidateAccountAmount(v.Block.Amount) == nil) != v.ScalarValid {
				t.Fatal("wrong amount scalar classification")
			}
			var rpcFields struct {
				Address string `json:"address"`
				Height  uint64 `json:"height"`
			}
			if err := json.Unmarshal(v.RPC, &rpcFields); err != nil {
				t.Fatal(err)
			}
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					ID json.RawMessage `json:"id"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					return
				}
				if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"list": []json.RawMessage{v.RPC}}}); err != nil {
					t.Error(err)
				}
			}))
			defer peer.Close()
			got, err := fetch.NewClient(peer.URL).FetchAccountBlocksByHeight(context.Background(), rpcFields.Address, rpcFields.Height, 1)
			if v.ScalarValid {
				if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], v.Block) {
					t.Fatalf("RPC conversion differs from node vector: %v", err)
				}
			} else if !errors.Is(err, chain.ErrInvalidAccountAmount) || got != nil {
				t.Fatalf("invalid node amount survived RPC: %v", err)
			}
			segment := proof.AccountSegment{Address: v.Block.Address, Blocks: []chain.AccountBlock{v.Block}}
			state := verify.HeaderState{Genesis: verify.GenesisTrustRoot{ChainID: v.Block.ChainIdentifier}}
			result := verify.VerifySegment(state, segment, nil, verify.DefaultPolicy())
			if !v.ScalarValid && (result.Worst() != verify.OutcomeReject || result.Blocks[0].Reason != verify.ReasonInvalidAmount) {
				t.Fatalf("signed invalid amount was not rejected before proof lookup: %v", result.Blocks)
			}
			if v.ScalarValid && result.Blocks[0].Reason != verify.ReasonMissingProof {
				t.Fatalf("valid scalar failed before missing evidence: %v", result.Blocks)
			}
		})
	}
}
