package conformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// The original fixture selects the requested account independently of the peer.
func accountBasicRPCUser(t *testing.T) accountSegmentVector {
	t.Helper()
	for _, segment := range loadNodeAccountCorpus(t, "account-segments.json").Segments {
		if len(segment.Vectors) == 2 && segment.Vectors[0].Name == "user-type-2" && segment.Vectors[1].Name == "user-type-3" {
			return segment
		}
	}
	t.Fatal("missing original signed user segment")
	return accountSegmentVector{}
}

func accountBasicRPCPeer(t *testing.T, address string, start uint64, rows []json.RawMessage) *fetch.Client {
	t.Helper()
	var calls atomic.Int32
	wantParams, err := json.Marshal([]any{address, start, uint64(len(rows))})
	if err != nil {
		t.Fatal(err)
	}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error("cannot decode selected loopback request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodPost || request.JSONRPC != "2.0" || !bytes.Equal(request.ID, []byte("1")) ||
			request.Method != "ledger.getAccountBlocksByHeight" || !bytes.Equal(request.Params, wantParams) {
			t.Error("request differs from the independently selected account/range")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": request.ID, "result": map[string]any{"list": rows},
		}); err != nil {
			t.Error("cannot encode selected loopback response")
		}
	}))
	client := fetch.NewClient(peer.URL)
	t.Cleanup(func() {
		client.HTTP.CloseIdleConnections()
		peer.Close()
		if calls.Load() != 1 {
			t.Error("selected read-only request was absent or repeated")
		}
	})
	return client
}

// Select expected errors by the immutable input profile, never by node MATCH.
// Hash-changing mutations retained the original claimed hash and signature.
func accountBasicRPCError(t *testing.T, profile string) error {
	t.Helper()
	switch profile {
	case "version-zero", "version-two":
		return chain.ErrUnsupportedAccountBlockVersion
	case "type-zero", "type-genesis", "type-unsupported":
		return chain.ErrUnsupportedAccountBlockType
	case "chain-zero", "type-contract-receive":
		return chain.ErrInvalidAccountBlockEnvelope
	case "amount-negative", "amount-large":
		return chain.ErrInvalidAccountAmount
	case "chain-mismatch", "token-zero", "send-from-hash-nonzero",
		"height-two-exact", "height-two-empty", "height-two-wrong-frontier",
		"height-two-corrupt-frontier", "height-two-previous-ack-ahead", "hash-zero", "hash-mutated":
		return fetch.ErrHashMismatch
	case "first-exact-ack", "stored-chain-mismatch", "ack-missing", "ack-wrong-hash", "ack-corrupt-entry", "signature-empty":
		return nil
	default:
		t.Fatal("unselected node account profile")
		return nil
	}
}

func TestNodeAccountBasicRPCBoundaries(t *testing.T) {
	user := accountBasicRPCUser(t)
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
	blocked, accepted, rejected := 0, 0, 0
	for _, row := range loadAccountBasicObservations(t) {
		t.Run(row.Name, func(t *testing.T) {
			start := uint64(1)
			if strings.HasPrefix(row.Profile, "height-two-") {
				start = 2
			}
			client := accountBasicRPCPeer(t, user.RPCAddress, start, []json.RawMessage{row.Wire})
			blocks, err := client.FetchAccountBlocksByHeight(context.Background(), user.RPCAddress, start, 1)
			if want := accountBasicRPCError(t, row.Profile); want != nil {
				if !errors.Is(err, want) || blocks != nil {
					t.Fatalf("node %s=%s; RPC returned %d blocks, error=%v; want=%v and no partial result", row.Method, row.NodeResult, len(blocks), err, want)
				}
				blocked++
			} else {
				if err != nil || len(blocks) != 1 {
					t.Fatalf("selected RPC conversion failed: %v", err)
				}
				want := accountBasicBlock(t, row)
				// Empty optional RPC byte fields are represented as nil by fetch.
				if len(want.Signature) == 0 {
					want.Signature = nil
				}
				if !reflect.DeepEqual(blocks[0], want) || blocks[0].ComputeHash() != row.ComputedHash {
					t.Fatal("production RPC conversion differs from the independently checked corpus projection")
				}
				result := state.VerifySegment(proof.AccountSegment{Address: user.Address, Blocks: blocks}, bundle.Commitments)
				if len(result.Blocks) != 1 {
					t.Fatal("unexpected SPV result inventory")
				}
				got := result.Blocks[0]
				if row.Profile == "signature-empty" {
					if result.Worst() != verify.OutcomeReject || got.Reason != verify.ReasonSignatureMissing || len(got.Proven) != 0 {
						t.Fatal("hash-checked transport or node MATCH bypassed signature validation")
					}
					rejected++
				} else {
					if result.Worst() != verify.OutcomeAccept || !slices.Contains(got.Proven, verify.GuaranteeContentInclusion) ||
						!slices.Contains(got.Proven, verify.GuaranteeSignatureAuthenticity) {
						t.Fatal("missing original commitment or signature guarantee")
					}
					assertBoundedGuarantees(t, got)
					accepted++
				}
			}
			if !reflect.DeepEqual(before, state.Snapshot()) {
				t.Fatal("RPC/segment query changed selected verified state")
			}
		})
	}
	if blocked != 38 || accepted != 10 || rejected != 2 {
		t.Fatalf("RPC-to-SPV boundary inventory differs: blocked=%d accepted=%d rejected=%d", blocked, accepted, rejected)
	}
}

func TestNodeAccountBasicRPCMatchCannotSupplyCommitmentInputs(t *testing.T) {
	user := accountBasicRPCUser(t)
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
	for _, row := range loadAccountBasicObservations(t) {
		if row.Profile != "first-exact-ack" {
			continue
		}
		selected++
		t.Run(row.Name, func(t *testing.T) {
			if row.NodeResult != "MATCH" {
				t.Fatal("selected positive node method observation missing")
			}
			client := accountBasicRPCPeer(t, user.RPCAddress, 1, []json.RawMessage{row.Wire})
			blocks, err := client.FetchAccountBlocksByHeight(context.Background(), user.RPCAddress, 1, 1)
			if err != nil || len(blocks) != 1 {
				t.Fatal("selected positive RPC conversion failed")
			}
			for _, tc := range []struct {
				name        string
				state       verify.VerifiedState
				commitments []proof.CommitmentEvidence
				reason      verify.ReasonCode
			}{
				{"header-not-retained", initial, bundle.Commitments, verify.ReasonHeightOutOfWindow},
				{"proof-not-supplied", retained, nil, verify.ReasonMissingProof},
			} {
				t.Run(tc.name, func(t *testing.T) {
					before := tc.state.Snapshot()
					result := tc.state.VerifySegment(proof.AccountSegment{Address: user.Address, Blocks: blocks}, tc.commitments)
					if len(result.Blocks) != 1 || result.Worst() != verify.OutcomeRefused || result.Blocks[0].Reason != tc.reason ||
						len(result.Blocks[0].Proven) != 0 || !reflect.DeepEqual(before, tc.state.Snapshot()) {
						t.Fatal("RPC conversion or node MATCH supplied missing commitment inputs")
					}
				})
			}
		})
	}
	if selected != 2 {
		t.Fatal("both positive node entry points must be checked")
	}
}

func TestNodeAccountBasicRPCDiscardsPartialRanges(t *testing.T) {
	user := accountBasicRPCUser(t)
	second := user.Vectors[1].RPC
	edit := func(field string, value any) json.RawMessage {
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(second, &wire); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		wire[field] = raw
		raw, err = json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var otherAccount json.RawMessage
	for _, segment := range loadNodeAccountCorpus(t, "account-segments.json").Segments {
		for _, vector := range segment.Vectors {
			if vector.Name == "embedded-type-4" && vector.Block.Height == 2 {
				otherAccount = vector.RPC
			}
		}
	}
	if len(otherAccount) == 0 {
		t.Fatal("missing original hash-consistent other-account control")
	}
	// These are additional transport controls, not new node method observations.
	for _, tc := range []struct {
		name string
		wire json.RawMessage
		err  error
	}{
		{"original-signed-range", second, nil},
		{"later-hash-mismatch", edit("hash", strings.Repeat("0", 64)), fetch.ErrHashMismatch},
		{"later-invalid-amount", edit("amount", "-1"), chain.ErrInvalidAccountAmount},
		{"later-unsupported-version", edit("version", 2), chain.ErrUnsupportedAccountBlockVersion},
		{"later-wrong-height", edit("height", 1), fetch.ErrQueryMismatch},
		{"later-other-account", otherAccount, fetch.ErrQueryMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := accountBasicRPCPeer(t, user.RPCAddress, 1, []json.RawMessage{user.Vectors[0].RPC, tc.wire})
			blocks, err := client.FetchAccountBlocksByHeight(context.Background(), user.RPCAddress, 1, 2)
			if tc.err != nil {
				if !errors.Is(err, tc.err) || blocks != nil {
					t.Fatalf("a valid first row leaked from a failed complete range: %v", err)
				}
			} else if err != nil || !reflect.DeepEqual(blocks, []chain.AccountBlock{user.Vectors[0].Block, user.Vectors[1].Block}) {
				t.Fatal("original independently signed range changed in RPC conversion")
			}
		})
	}
}
