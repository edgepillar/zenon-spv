// SPDX-License-Identifier: MIT

package fetch

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/proof"
)

func candidateSettlementFields(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	zero := candidateRPCJSON(t, strings.Repeat("0", 64))
	return map[string]json.RawMessage{
		"domainId": json.RawMessage("1"), "batchId": json.RawMessage("7"), "protocolVersion": json.RawMessage("1"),
		"firstInputSeq": json.RawMessage("10"), "lastInputSeq": json.RawMessage("20"),
		"preStateRoot": zero, "postStateRoot": zero, "inputRoot": zero, "receiptRoot": zero, "eventRoot": zero, "outboxRoot": zero, "daHash": zero,
		"daMode": json.RawMessage("1"), "executorPillar": candidateRPCJSON(t, "recorded-executor"), "submittedAtHeight": json.RawMessage("12"), "finalizeAtHeight": json.RawMessage("100"),
		"assetFlowSummary": candidateRPCJSON(t, []byte{1, 2}), "proofData": candidateRPCJSON(t, []byte{3, 4}), "state": json.RawMessage("2"), "isFinalized": json.RawMessage("true"),
	}
}

func TestCandidateSettlementBatchExactSchema(t *testing.T) {
	fields := candidateSettlementFields(t)
	for field := range fields {
		for _, kind := range []string{"missing", "null", "duplicate", "case-alias"} {
			t.Run(field+"/"+kind, func(t *testing.T) {
				v := candidateRPCFields(t, string(candidateRPCJSON(t, fields)))
				switch kind {
				case "missing":
					delete(v, field)
				case "null":
					v[field] = json.RawMessage("null")
				case "case-alias":
					v[strings.ToUpper(field)] = v[field]
					delete(v, field)
				}
				raw := candidateRPCJSON(t, v)
				if kind == "duplicate" {
					raw = append(raw[:len(raw)-1], ',')
					raw = append(raw, candidateRPCJSON(t, field)...)
					raw = append(raw, ':')
					raw = append(raw, v[field]...)
					raw = append(raw, '}')
				}
				result, err := DecodeCandidateSettlementBatch(raw)
				if kind == "null" && (field == "assetFlowSummary" || field == "proofData") {
					if err != nil {
						t.Fatal("nil source byte field rejected", err)
					}
					return
				}
				if err == nil || !reflect.DeepEqual(result, proof.CandidateSettlementBatch{}) {
					t.Fatal("ambiguous frontier DTO supplied fields", err)
				}
			})
		}
	}
	for field, value := range map[string]json.RawMessage{
		"domainId": json.RawMessage("4294967296"), "batchId": json.RawMessage("18446744073709551616"), "protocolVersion": json.RawMessage("65536"),
		"firstInputSeq": json.RawMessage("-1"), "lastInputSeq": json.RawMessage("1.0"), "daMode": json.RawMessage("256"), "state": json.RawMessage("256"),
		"isFinalized": json.RawMessage("1"), "preStateRoot": candidateRPCJSON(t, strings.Repeat("A", 64)), "executorPillar": candidateRPCJSON(t, strings.Repeat("x", 4097)),
		"assetFlowSummary": candidateRPCJSON(t, make([]byte, 4097)), "proofData": candidateRPCJSON(t, make([]byte, 4097)),
	} {
		t.Run(field+"/width", func(t *testing.T) {
			v := candidateSettlementFields(t)
			v[field] = value
			result, err := DecodeCandidateSettlementBatch(candidateRPCJSON(t, v))
			if err == nil || !reflect.DeepEqual(result, proof.CandidateSettlementBatch{}) {
				t.Fatal("invalid DTO field accepted", err)
			}
		})
	}
	if result, err := DecodeCandidateSettlementBatch([]byte("null")); err != ErrCandidateStateUnavailable || !reflect.DeepEqual(result, proof.CandidateSettlementBatch{}) {
		t.Fatal("missing frontier row became a typed zero", err)
	}
}

func TestCandidateSettlementBatchSelectedIDsAndFrontierHint(t *testing.T) {
	for _, kind := range []string{"recorded", "domain", "batch", "unavailable", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			v := candidateSettlementFields(t)
			var body any = v
			padding := -1
			switch kind {
			case "domain":
				v["domainId"] = json.RawMessage("2")
			case "batch":
				v["batchId"] = json.RawMessage("8")
			case "unavailable":
				body = nil
			case "oversized":
				padding = 1
			}
			client, _ := candidateStateTransport(t, "embedded.settlement.getBatch", []any{uint32(1), uint64(7)}, body, padding)
			result, err := client.FetchCandidateSettlementBatch(context.Background(), 1, 7)
			switch kind {
			case "recorded":
				if err != nil || result.DomainID != 1 || result.BatchID != 7 || result.Entry.FinalizeAtHeight != 100 || !result.IsFinalized {
					t.Fatal("frontier DTO changed", err)
				}
			case "domain", "batch":
				if !errors.Is(err, ErrQueryMismatch) || !reflect.DeepEqual(result, proof.CandidateSettlementBatch{}) {
					t.Fatal("selected key identity changed", err)
				}
			case "unavailable":
				if !errors.Is(err, ErrCandidateStateUnavailable) || !reflect.DeepEqual(result, proof.CandidateSettlementBatch{}) {
					t.Fatal("missing DTO became application absence", err)
				}
			case "oversized":
				if !errors.Is(err, ErrResponseTooLarge) || !reflect.DeepEqual(result, proof.CandidateSettlementBatch{}) {
					t.Fatal("oversized whole DTO accepted", err)
				}
			}
		})
	}
	v := candidateSettlementFields(t)
	raw := candidateRPCJSON(t, v)
	client, _ := candidateStateTransport(t, "embedded.settlement.getBatch", []any{uint32(1), uint64(7)}, v, 0)
	if _, err := client.FetchCandidateSettlementBatch(context.Background(), 1, 7); err != nil {
		t.Fatal("exact DTO body budget", err)
	}
	if _, err := DecodeCandidateSettlementBatch(append(raw, []byte("{}")...)); err == nil {
		t.Fatal("trailing DTO accepted")
	}
}
