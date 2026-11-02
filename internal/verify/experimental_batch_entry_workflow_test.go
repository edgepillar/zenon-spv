// SPDX-License-Identifier: MIT

package verify_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func experimentalBatchPublicState(t *testing.T) (verify.ExperimentalV3State, []chain.CandidateV3Header) {
	t.Helper()
	raw, err := os.ReadFile("../testdata/conformance/first-v3-node-headers.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if len(raw) != 21634 || hex.EncodeToString(digest[:]) != "78222ac4bba092fc9f4b6775d158a8e5d013c22b7e7a85948dce6453f26cff12" {
		t.Fatal("public header fixture changed")
	}
	var file struct {
		Trace struct {
			ChainID uint64     `json:"chain_id"`
			Genesis chain.Hash `json:"genesis_hash"`
			Rows    []struct {
				Height  uint64
				Version uint64
				Hash    chain.Hash
				Header  json.RawMessage
			}
		}
	}
	if json.Unmarshal(raw, &file) != nil || file.Trace.ChainID != 100 {
		t.Fatal("fixture shape")
	}
	p := verify.ExperimentalV3Profile{Version: 1, Genesis: verify.GenesisTrustRoot{ChainID: 100, Height: 1, HeaderHash: file.Trace.Genesis},
		FirstV3Height: 12, ValidThrough: 14, NodeRevision: verify.ExperimentalV3NodeRevision, Source: "recorded isolated chain-100 fixture, not network activation"}
	var headers []chain.CandidateV3Header
	var entries []verify.ProducerEntry
	for _, row := range file.Trace.Rows {
		if row.Height == 11 {
			p.Anchor = verify.GenesisTrustRoot{ChainID: 100, Height: 11, HeaderHash: row.Hash}
		}
		if row.Version == 3 {
			h, err := chain.DecodeCandidateV3Header(row.Header)
			if err != nil {
				t.Fatal(err)
			}
			headers = append(headers, h)
			entries = append(entries, verify.ProducerEntry{Height: h.Header.Height, TimestampUnix: h.Header.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.Header.PublicKey)})
		}
	}
	schedule, err := verify.NewProducerSchedule(100, []verify.ProducerCoverage{{FromHeight: 12, ThroughHeight: 14}}, entries, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := verify.ExperimentalV3Policy{W: 1, RetainHeaders: 2, MaxBatchHeaders: 3}
	context, err := verify.ExperimentalV3ContextFor(p, policy, schedule)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := verify.NewExperimentalV3State(p, policy, schedule, context.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	accepted, state := initial.Extend(headers)
	if accepted.Outcome != verify.OutcomeAccept {
		t.Fatal(accepted)
	}
	return state, headers
}

func TestExperimentalBatchEntryRecordedRPCRefusalWorkflow(t *testing.T) {
	// Complete exported-API refusal flow with real recorded public signatures.
	// The empty-tree witness is valid mathematical absence for another root;
	// it is not a matching BatchEntry witness for these signed headers.
	state, headers := experimentalBatchPublicState(t)
	p := verify.ExperimentalBatchEntryProfile{Version: 1, Settlement: verify.ExperimentalBatchEntrySettlementAddress(), DomainID: 1,
		RuntimeIdentity: chain.Hash{0x42, 0xab}, MaxProofBytes: proof.CandidateSMTMaxProofBytes, MaxSiblings: 256,
		Limits: verify.ExperimentalBatchEntryLimits{MaxValueBytes: 4096, MaxExecutorPillarBytes: 256, MaxAssetFlowSummaryBytes: 1024,
			MaxProofDataBytes: 1024, MaxDynamicBytes: 2048, StringRule: proof.CandidateBatchEntryUTF8String},
		Source: "synthetic query selection; no actual selected runtime or live BatchEntry"}
	contextPin, err := verify.ExperimentalBatchEntryContextFor(state, p)
	if err != nil {
		t.Fatal(err)
	}
	query, err := verify.NewExperimentalBatchEntryQuery(state, p, contextPin.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	request := verify.ExperimentalBatchEntryRequest{Context: contextPin.Fingerprint, Height: 13, HeaderHash: headers[1].Header.HeaderHash,
		TipHeight: 14, TipHash: headers[2].Header.HeaderHash, BatchID: 1}
	key := proof.CandidateSettlementBatchEntryKey(p.Settlement, p.DomainID, request.BatchID)
	path := proof.CandidateSettlementBatchEntryPath(p.Settlement, p.DomainID, request.BatchID)
	raw := make([]byte, 99)
	copy(raw[1:33], path[:])
	for _, kind := range []string{"untrusted-root", "copied-owned-root", "missing"} {
		t.Run(kind, func(t *testing.T) {
			client := fetch.NewClient("https://candidate.invalid")
			calls := 0
			client.HTTP.Transport = experimentalV3Transport(func(req *http.Request) (*http.Response, error) {
				calls++
				var call struct {
					Method string
					Params []json.RawMessage
				}
				if json.NewDecoder(req.Body).Decode(&call) != nil || call.Method != "ledger.getProof" || len(call.Params) != 2 {
					t.Fatal("selected proof read changed")
				}
				var height uint64
				var selected []byte
				if json.Unmarshal(call.Params[0], &height) != nil || json.Unmarshal(call.Params[1], &selected) != nil || height != 13 || !bytes.Equal(selected, key[:]) {
					t.Fatal("local query key changed")
				}
				root := chain.Hash{}
				if kind == "copied-owned-root" {
					root = headers[1].StateRoot
				}
				var result any = map[string]any{"root": root, "value": nil, "proof": raw}
				if kind == "missing" {
					result = nil
				}
				body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
			})
			witness, err := client.FetchCandidateBatchEntryProof(context.Background(), request.Height, p.Settlement, p.DomainID, request.BatchID)
			if calls != 1 {
				t.Fatal("proof request not observed")
			}
			if kind == "missing" {
				if !errors.Is(err, fetch.ErrCandidateStateUnavailable) || !reflect.DeepEqual(witness, proof.CandidateStateWitness{}) {
					t.Fatal("missing witness became absence", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			result, err := query.QueryWitness(request, witness)
			if err == nil || !reflect.DeepEqual(result, verify.ExperimentalBatchEntryResult{}) {
				t.Fatal("candidate root/proof supplied a consumer row", err)
			}
			if kind == "untrusted-root" && !errors.Is(err, verify.ErrExperimentalBatchEntryWitnessRoot) {
				t.Fatal(err)
			}
			if kind == "copied-owned-root" && !errors.Is(err, proof.ErrCandidateSMTMismatch) {
				t.Fatal(err)
			}
			// A gateway may agree with the selected IDs and claim finalized.
			// Neither agreement nor its frontier hint can bypass the proof.
			result, err = query.QueryWithGateway(request, witness, proof.CandidateSettlementBatch{DomainID: p.DomainID, BatchID: request.BatchID, IsFinalized: true})
			if err == nil || !reflect.DeepEqual(result, verify.ExperimentalBatchEntryResult{}) {
				t.Fatal("frontier hint supplied typed authority")
			}
		})
	}
}
