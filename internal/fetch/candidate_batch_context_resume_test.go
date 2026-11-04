// SPDX-License-Identifier: MIT

package fetch

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// These are transport controls. Candidate proof framing is not authenticated
// membership, and the recorded header signatures are never regenerated.
func contextResumeClient(t *testing.T, rows []json.RawMessage, selected CandidateBatchCollectionSelection, mode string) (*Client, *[]string) {
	t.Helper()
	client := NewClient("https://selected.invalid")
	var methods []string
	proofs := 0
	client.HTTP.Transport = diagnosticTransport(func(request *http.Request) (*http.Response, error) {
		var call struct {
			Method string
			Params []json.RawMessage
		}
		if json.NewDecoder(request.Body).Decode(&call) != nil {
			t.Fatal("request encoding")
		}
		methods = append(methods, call.Method)
		var result any
		switch call.Method {
		case "ledger.getMomentumsByHeight":
			var start, count uint64
			if len(call.Params) != 2 || json.Unmarshal(call.Params[0], &start) != nil || json.Unmarshal(call.Params[1], &count) != nil || start < 12 || count == 0 || count > 3 || start-12+count > 3 {
				t.Fatal("unexpected successor range")
			}
			members := rows[start-12 : start-12+count]
			if mode == "short" {
				members = members[:len(members)-1]
			}
			result = map[string]any{"list": members, "count": len(members)}
		case "ledger.getProof":
			var height uint64
			var key []byte
			if len(call.Params) != 2 || json.Unmarshal(call.Params[0], &height) != nil || json.Unmarshal(call.Params[1], &key) != nil || height != selected.Height || proofs >= 3 {
				t.Fatal("proof selector or count")
			}
			suffix := []string{"02000000010000000000000001", "0100000001", "1500000001"}[proofs]
			if hex.EncodeToString(key) != "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c004"+suffix {
				t.Fatal("three locally derived full keys changed")
			}
			proofs++
			result = map[string]any{"root": strings.Repeat("0", 64), "value": nil, "proof": make([]byte, 99)}
			if mode == "last-error" && proofs == 3 {
				result = nil
			}
		case "embedded.settlement.getBatch":
			fields := candidateSettlementFields(t)
			fields["batchId"] = json.RawMessage("1")
			result = fields
		default:
			t.Fatal("unexpected request")
		}
		raw := collectionReply(t, result)
		if mode == "oversize" && call.Method == "ledger.getProof" {
			raw = append(bytes.Repeat([]byte(" "), int(MaxCandidateStateResponseBytes)), raw...)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})
	return client, &methods
}

func TestCandidateBatchContextResumeRanges(t *testing.T) {
	rows, selected := collectionFixture(t)
	points := []CandidateBatchContextResume{{selected.AnchorHeight, selected.AnchorHash}}
	for _, raw := range rows {
		row, err := DecodeCandidateV3Momentum(raw)
		if err != nil {
			t.Fatal(err)
		}
		points = append(points, CandidateBatchContextResume{row.Header.Header.Height, row.Header.Header.HeaderHash})
	}
	for i, point := range points {
		t.Run([]string{"original-anchor", "two-successors", "one-successor", "proof-only"}[i], func(t *testing.T) {
			client, methods := contextResumeClient(t, rows, selected, "")
			raw, err := client.FetchCandidateBatchContextBundleAfter(context.Background(), selected, point, false)
			var doc struct {
				Momentums []json.RawMessage
				Witnesses map[string]json.RawMessage
			}
			if err != nil || json.Unmarshal(raw, &doc) != nil || doc.Momentums == nil || len(doc.Momentums) != 3-i || len(doc.Witnesses) != 3 {
				t.Fatal("resumed document incomplete", err)
			}
			want := []string{"ledger.getProof", "ledger.getProof", "ledger.getProof"}
			if i < 3 {
				want = append([]string{"ledger.getMomentumsByHeight"}, want...)
			}
			if !reflect.DeepEqual(*methods, want) {
				t.Fatal("header traffic was not reduced", *methods)
			}
			for n, raw := range doc.Momentums {
				var a, b bytes.Buffer
				_ = json.Compact(&a, raw)
				_ = json.Compact(&b, rows[i+n])
				if !bytes.Equal(a.Bytes(), b.Bytes()) {
					t.Fatal("recorded successor bytes changed")
				}
			}
		})
	}
}

func TestCandidateBatchContextResumePreflight(t *testing.T) {
	_, selected := collectionFixture(t)
	point := CandidateBatchContextResume{selected.TipHeight, selected.TipHash}
	for _, name := range []string{"zero-height", "zero-hash", "below-anchor", "above-tip", "anchor-hash", "query-hash", "tip-hash", "domain-zero", "query-before-anchor", "query-after-tip", "query-tip-hash", "range-limit"} {
		t.Run(name, func(t *testing.T) {
			s, after := selected, point
			switch name {
			case "zero-height":
				after.Height = 0
			case "zero-hash":
				after.Hash = chain.Hash{}
			case "below-anchor":
				after.Height = selected.AnchorHeight - 1
			case "above-tip":
				after.Height++
			case "anchor-hash":
				after.Height = selected.AnchorHeight
			case "query-hash":
				after.Height = selected.Height
			case "tip-hash":
				after.Hash = chain.Hash{8}
			case "domain-zero":
				s.DomainID = 0
			case "query-before-anchor":
				s.Height = s.AnchorHeight
			case "query-after-tip":
				s.Height = s.TipHeight + 1
			case "query-tip-hash":
				s.Height = s.TipHeight
			case "range-limit":
				s.TipHeight = selected.AnchorHeight + MaxCandidateV3RangeHeaders + 1
				after = CandidateBatchContextResume{selected.AnchorHeight, selected.AnchorHash}
			}
			client := NewClient("https://unused.invalid")
			calls := 0
			client.HTTP.Transport = diagnosticTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected transport") })
			if raw, err := client.FetchCandidateBatchContextBundleAfter(context.Background(), s, after, false); !errors.Is(err, ErrInvalidQuery) || raw != nil || calls != 0 {
				t.Fatal("invalid continuation reached transport")
			}
		})
	}
	after := CandidateBatchContextResume{selected.AnchorHeight + 1, chain.Hash{8}}
	selected.TipHeight = after.Height + MaxCandidateV3RangeHeaders
	if selected.ValidateContextResume(after) != nil || selected.Validate() == nil {
		t.Fatal("actual suffix limit was replaced by original history length")
	}
	selected.TipHeight++
	if selected.ValidateContextResume(after) == nil {
		t.Fatal("one-extra successor accepted")
	}
}

func TestCandidateBatchContextResumeProofOnlyUint64(t *testing.T) {
	for _, height := range []uint64{MaxCandidateV3RangeHeaders + 1000, math.MaxUint64} {
		rows, selected := collectionFixture(t)
		selected.Height, selected.TipHeight, selected.HeaderHash = height, height, selected.TipHash
		if selected.Validate() == nil {
			t.Fatal("legacy complete-range bound changed")
		}
		client, methods := contextResumeClient(t, rows, selected, "")
		raw, err := client.FetchCandidateBatchContextBundleAfter(context.Background(), selected, CandidateBatchContextResume{height, selected.TipHash}, true)
		var doc map[string]json.RawMessage
		if err != nil || json.Unmarshal(raw, &doc) != nil || string(doc["momentums"]) != "[]" || len(doc) != 4 ||
			!reflect.DeepEqual(*methods, []string{"ledger.getProof", "ledger.getProof", "ledger.getProof", "embedded.settlement.getBatch"}) {
			t.Fatal("proof-only collection overflowed or inferred header authority", err)
		}
	}
}

func TestCandidateBatchContextResumeCompletion(t *testing.T) {
	for _, name := range []string{"broken-link", "wrong-query", "wrong-tip", "short", "last-error", "oversize", "canceled-before", "canceled-after-proof"} {
		t.Run(name, func(t *testing.T) {
			rows, selected := collectionFixture(t)
			row, err := DecodeCandidateV3Momentum(rows[0])
			if err != nil {
				t.Fatal(err)
			}
			after := CandidateBatchContextResume{row.Header.Header.Height, row.Header.Header.HeaderHash}
			switch name {
			case "broken-link":
				after.Hash = chain.Hash{8}
			case "wrong-query":
				selected.HeaderHash = chain.Hash{8}
			case "wrong-tip":
				selected.TipHash = chain.Hash{8}
			case "short":
				// Keep the requested two-header suffix for the short response.
			default:
				after = CandidateBatchContextResume{selected.TipHeight, selected.TipHash}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client, methods := contextResumeClient(t, rows, selected, name)
			switch name {
			case "canceled-before":
				cancel()
			case "canceled-after-proof":
				original := client.HTTP.Transport
				client.HTTP.Transport = diagnosticTransport(func(req *http.Request) (*http.Response, error) {
					response, err := original.RoundTrip(req)
					cancel()
					return response, err
				})
			}
			if raw, err := client.FetchCandidateBatchContextBundleAfter(ctx, selected, after, false); err == nil || raw != nil {
				t.Fatal("failed continuation returned partial document")
			}
			if name == "canceled-before" && len(*methods) != 0 || name == "canceled-after-proof" && len(*methods) != 1 {
				t.Fatal("cancellation made additional requests")
			}
		})
	}
}
