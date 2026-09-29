package conformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type accountSegmentVector struct {
	Name       string        `json:"name"`
	Address    chain.Address `json:"address"`
	RPCAddress string        `json:"rpc_address"`
	Vectors    []struct {
		Name  string             `json:"name"`
		RPC   json.RawMessage    `json:"rpc"`
		Block chain.AccountBlock `json:"block"`
	} `json:"vectors"`
}

type accountSegmentCorpus struct {
	FormatVersion int                     `json:"format_version"`
	Source        struct{ Commit string } `json:"source"`
	Chain         momentumSeries          `json:"chain"`
	Segments      []accountSegmentVector  `json:"segments"`
	Batches       []struct {
		ReceiveHeight uint64           `json:"receive_height"`
		Previous      chain.HashHeight `json:"previous"`
		CommitHeights []uint64         `json:"commit_heights"`
	} `json:"batches"`
}

func loadNodeAccountCorpus(t *testing.T, filename string) accountSegmentCorpus {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../testdata/conformance", filename))
	if err != nil {
		t.Fatal(err)
	}
	var c accountSegmentCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.FormatVersion != 1 || c.Source.Commit != "3a4131e63881058b6ce2ee81d3a41d0033fafc99" || len(c.Chain.Vectors) != 9 || len(c.Segments) == 0 {
		t.Fatal("unexpected account segment corpus")
	}
	return c
}

func accountBundleFromCorpus(t *testing.T, c accountSegmentCorpus) proof.HeaderBundle {
	t.Helper()
	detailed, err := fetchVectors(t, c.Chain.Vectors)
	if err != nil {
		t.Fatal(err)
	}
	bundle := proof.HeaderBundle{Version: proof.WireVersion, ChainID: c.Chain.Anchor.ChainID, ClaimedGenesis: c.Chain.Anchor.HeaderHash}
	for i, d := range detailed {
		if !reflect.DeepEqual(d.Header, c.Chain.Vectors[i].Header) || !slices.Equal(d.Content, c.Chain.Vectors[i].Content) {
			t.Fatal("RPC momentum differs from node vector")
		}
		bundle.Headers = append(bundle.Headers, d.Header)
		for _, member := range d.Content {
			bundle.Commitments = append(bundle.Commitments, proof.CommitmentEvidence{
				Height: d.Header.Height, Target: member, Flat: &proof.FlatContentEvidence{SortedHeaders: d.Content},
			})
		}
	}
	for _, segment := range c.Segments {
		if len(segment.Vectors) == 0 {
			t.Fatal("incomplete account segment")
		}
		blocks := fetchAccountSegmentVectors(t, segment)
		for i, b := range blocks {
			want := segment.Vectors[i].Block
			if !reflect.DeepEqual(b, want) || b.ComputeHash() != want.BlockHash {
				t.Fatalf("RPC conversion or hash differs for %s", segment.Vectors[i].Name)
			}
		}
		bundle.Segments = append(bundle.Segments, proof.AccountSegment{Address: segment.Address, Blocks: blocks})
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := proof.UnmarshalHeaderBundleJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func nodeAccountBundle(t *testing.T) (verify.GenesisTrustRoot, proof.HeaderBundle) {
	t.Helper()
	c := loadNodeAccountCorpus(t, "account-segments.json")
	if len(c.Segments) != 2 {
		t.Fatal("unexpected account segment count")
	}
	types := map[uint64]bool{}
	for _, segment := range c.Segments {
		if len(segment.Vectors) != 2 {
			t.Fatal("incomplete account segment")
		}
		for _, v := range segment.Vectors {
			types[v.Block.BlockType] = true
		}
	}
	bundle := accountBundleFromCorpus(t, c)
	if len(types) != 4 || !types[2] || !types[3] || !types[4] || !types[5] || len(bundle.Commitments) != 4 {
		t.Fatal("missing account types or inclusion evidence")
	}
	return c.Chain.Anchor, bundle
}

func fetchAccountSegmentVectors(t *testing.T, segment accountSegmentVector) []chain.AccountBlock {
	t.Helper()
	blocks, err := tryFetchAccountSegmentVectors(t, segment)
	if err != nil {
		t.Fatal(err)
	}
	return blocks
}

func tryFetchAccountSegmentVectors(t *testing.T, segment accountSegmentVector) ([]chain.AccountBlock, error) {
	t.Helper()
	wire := make([]json.RawMessage, len(segment.Vectors))
	for i, v := range segment.Vectors {
		wire[i] = v.RPC
	}
	start, count := segment.Vectors[0].Block.Height, uint64(len(wire))
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		want, _ := json.Marshal([]any{segment.RPCAddress, start, count})
		if req.Method != "ledger.getAccountBlocksByHeight" || !bytes.Equal(req.Params, want) {
			t.Error("unexpected account query")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"list": wire}}); err != nil {
			t.Error(err)
		}
	}))
	defer peer.Close()
	return fetch.NewClient(peer.URL).FetchAccountBlocksByHeight(context.Background(), segment.RPCAddress, start, count)
}

func TestNodeAccountSegmentsThroughRPCBundleAndTrustedResume(t *testing.T) {
	anchor, bundle := nodeAccountBundle(t)
	opts := verify.VerifyOptions{Policy: verify.DefaultPolicy()}
	initial, err := verify.NewVerifiedState(anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	r, shallow := initial.Extend(bundle.Headers[:len(bundle.Headers)-1])
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	for _, segment := range bundle.Segments {
		result := shallow.VerifySegment(segment, bundle.Commitments)
		if result.Blocks[0].Outcome != verify.OutcomeRefused || result.Blocks[0].Reason != verify.ReasonInsufficientFinality || result.Blocks[1].Reason != verify.ReasonParentNotAccepted {
			t.Fatalf("shallow node-derived commitment was accepted: %v", result.Blocks)
		}
	}
	r, state := shallow.Extend(bundle.Headers[len(bundle.Headers)-1:])
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	resumed, err := verify.LoadTrustedState(path, anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	for handleIndex, handle := range []verify.VerifiedState{state, resumed} {
		for _, segment := range bundle.Segments {
			for _, blocks := range [][]chain.AccountBlock{segment.Blocks, segment.Blocks[1:]} {
				result := handle.VerifySegment(proof.AccountSegment{Address: segment.Address, Blocks: blocks}, bundle.Commitments)
				for _, r := range result.Blocks {
					if r.Outcome != verify.OutcomeAccept || !slices.Contains(r.Proven, verify.GuaranteeContentInclusion) {
						t.Fatal(r)
					}
					if slices.Contains(r.Proven, verify.GuaranteeSignatureAuthenticity) == segment.Address.IsEmbeddedAddress() {
						t.Fatal("wrong user/embedded signature guarantee")
					}
					if !slices.Contains(r.TrustAssumptions, verify.TrustConfiguredAnchor) {
						t.Fatal("missing anchor provenance assumption")
					}
					if handleIndex == 1 && !slices.Contains(r.TrustAssumptions, verify.TrustPersistedState) {
						t.Fatal("resume omitted persisted-state provenance")
					}
					assertBoundedGuarantees(t, r)
				}
			}
		}
	}
	for _, segment := range bundle.Segments {
		signatureReason := verify.ReasonInvalidSignature
		if segment.Address.IsEmbeddedAddress() {
			signatureReason = verify.ReasonEmbeddedMustNotSign
		}
		for _, tc := range []struct {
			name    string
			edit    func(*chain.AccountBlock)
			outcome verify.Outcome
			reason  verify.ReasonCode
		}{
			{"data hash", func(b *chain.AccountBlock) { b.DataHash[0] ^= 1 }, verify.OutcomeReject, verify.ReasonInvalidHash},
			{"wrong chain", func(b *chain.AccountBlock) { b.ChainIdentifier++ }, verify.OutcomeReject, verify.ReasonChainIDMismatch},
			{"unknown layout", func(b *chain.AccountBlock) { b.Version = 2 }, verify.OutcomeRefused, verify.ReasonUnsupportedAccountBlockVersion},
			{"signature", func(b *chain.AccountBlock) {
				if b.Address.IsEmbeddedAddress() {
					b.Signature = []byte{1}
				} else {
					b.Signature = slices.Clone(b.Signature)
					b.Signature[0] ^= 1
				}
			}, verify.OutcomeReject, signatureReason},
		} {
			t.Run(fmt.Sprintf("%s/%x", tc.name, segment.Address), func(t *testing.T) {
				bad := proof.AccountSegment{Address: segment.Address, Blocks: slices.Clone(segment.Blocks)}
				tc.edit(&bad.Blocks[0])
				result := resumed.VerifySegment(bad, bundle.Commitments)
				if result.Blocks[0].Outcome != tc.outcome || result.Blocks[0].Reason != tc.reason || len(result.Blocks[0].Proven) != 0 || result.Blocks[1].Outcome != tc.outcome || result.Blocks[1].Reason != verify.ReasonParentNotAccepted || len(result.Blocks[1].Proven) != 0 {
					t.Fatalf("tampered corpus gained acceptance or advanced its parent: %v", result.Blocks)
				}
			})
		}
	}
}
