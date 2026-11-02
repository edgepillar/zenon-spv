// SPDX-License-Identifier: MIT

package fetch

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func candidateWitnessFields(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	return map[string]json.RawMessage{"root": candidateRPCJSON(t, strings.Repeat("0", 64)), "value": json.RawMessage("null"), "proof": candidateRPCJSON(t, make([]byte, 99))}
}

func candidateStateTransport(t *testing.T, method string, params any, result any, padding int) (*Client, *int) {
	t.Helper()
	calls := 0
	client := NewClient("https://candidate.invalid")
	client.HTTP.Transport = diagnosticTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		var call struct {
			Method string
			Params json.RawMessage
		}
		if json.NewDecoder(req.Body).Decode(&call) != nil || call.Method != method {
			t.Fatal("unexpected read method")
		}
		var actual, want any
		if json.Unmarshal(call.Params, &actual) != nil || json.Unmarshal(candidateRPCJSON(t, params), &want) != nil || !reflect.DeepEqual(actual, want) {
			t.Fatal("selected RPC parameters changed")
		}
		raw := candidateRPCJSON(t, map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
		if padding >= 0 {
			raw = append(bytes.Repeat([]byte{' '}, int(MaxCandidateStateResponseBytes)-len(raw)+padding), raw...)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})
	return client, &calls
}

func TestCandidateStateWitnessExactSchema(t *testing.T) {
	fields := candidateWitnessFields(t)
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
				result, err := DecodeCandidateStateWitness(raw)
				if field == "value" && kind == "null" {
					if err != nil || result.Value != nil || len(result.Proof) != 99 {
						t.Fatal("source absence null was rejected", err)
					}
					return
				}
				if err == nil || !reflect.DeepEqual(result, proof.CandidateStateWitness{}) {
					t.Fatal("ambiguous candidate witness returned data", err)
				}
			})
		}
	}
	for _, kind := range []string{"unknown", "trailing", "root-upper", "root-prefix", "proof-short", "proof-large", "proof-noncanonical-base64", "value-large", "value-wrong-type"} {
		t.Run(kind, func(t *testing.T) {
			v := candidateWitnessFields(t)
			switch kind {
			case "unknown":
				v["private-field-marker"] = json.RawMessage("true")
			case "root-upper":
				v["root"] = candidateRPCJSON(t, strings.Repeat("A", 64))
			case "root-prefix":
				v["root"] = candidateRPCJSON(t, "0x"+strings.Repeat("0", 64))
			case "proof-short":
				v["proof"] = candidateRPCJSON(t, make([]byte, 98))
			case "proof-large":
				v["proof"] = candidateRPCJSON(t, make([]byte, proof.CandidateSMTMaxProofBytes+1))
			case "proof-noncanonical-base64":
				v["proof"] = candidateRPCJSON(t, base64.StdEncoding.EncodeToString(make([]byte, 99))+"\n")
			case "value-large":
				v["value"] = candidateRPCJSON(t, make([]byte, 4097))
			case "value-wrong-type":
				v["value"] = json.RawMessage("[]")
			}
			raw := candidateRPCJSON(t, v)
			if kind == "trailing" {
				raw = append(raw, []byte("{}")...)
			}
			result, err := DecodeCandidateStateWitness(raw)
			if err == nil || !reflect.DeepEqual(result, proof.CandidateStateWitness{}) || strings.Contains(err.Error(), "private-field-marker") {
				t.Fatal("invalid candidate witness returned or leaked data", err)
			}
		})
	}
	if result, err := DecodeCandidateStateWitness([]byte("null")); err != ErrCandidateStateUnavailable || !reflect.DeepEqual(result, proof.CandidateStateWitness{}) {
		t.Fatal("null result became absence", err)
	}
}

func TestCandidateStateWitnessSelectedReadAndByteBudget(t *testing.T) {
	address := chain.Address{1, 2, 3}
	key := proof.CandidateSettlementBatchEntryKey(address, 0x01020304, 0x0102030405060708)
	for _, padding := range []int{-1, 0, 1} {
		client, calls := candidateStateTransport(t, "ledger.getProof", []any{uint64(13), key[:]}, candidateWitnessFields(t), padding)
		result, err := client.FetchCandidateBatchEntryProof(context.Background(), 13, address, 0x01020304, 0x0102030405060708)
		if *calls != 1 {
			t.Fatal("unexpected request count")
		}
		if padding == 1 {
			if !errors.Is(err, ErrResponseTooLarge) || !reflect.DeepEqual(result, proof.CandidateStateWitness{}) {
				t.Fatal("oversized whole response was accepted", err)
			}
		} else if err != nil || result.Value != nil || len(result.Proof) != 99 {
			t.Fatal("bounded candidate read failed", err)
		}
	}
	client, calls := candidateStateTransport(t, "ledger.getProof", []any{uint64(13), key[:]}, nil, -1)
	result, err := client.FetchCandidateBatchEntryProof(context.Background(), 13, address, 0x01020304, 0x0102030405060708)
	if *calls != 1 || !errors.Is(err, ErrCandidateStateUnavailable) || !reflect.DeepEqual(result, proof.CandidateStateWitness{}) {
		t.Fatal("missing response supplied an absence", err)
	}
	before := *calls
	result, err = client.FetchCandidateBatchEntryProof(context.Background(), 0, address, 0, 0)
	if !errors.Is(err, ErrInvalidQuery) || *calls != before || !reflect.DeepEqual(result, proof.CandidateStateWitness{}) {
		t.Fatal("zero height reached transport", err)
	}
}

func TestCandidateStateWitnessIndependentResponseLimits(t *testing.T) {
	client := NewClient("https://candidate.invalid")
	fields := candidateWitnessFields(t)
	calls := 0
	client.HTTP.Transport = diagnosticTransport(func(*http.Request) (*http.Response, error) {
		calls++
		body := candidateRPCJSON(t, map[string]any{"jsonrpc": "2.0", "id": 1, "result": fields})
		body = append(bytes.Repeat([]byte{' '}, int(MaxCandidateStateResponseBytes)-len(body)), body...)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
	})
	for i := 0; i < 2; i++ {
		if _, err := client.FetchCandidateBatchEntryProof(context.Background(), 13, chain.Address{1}, 1, 1); err != nil {
			t.Fatal("a previous query consumed this query's transport budget", err)
		}
	}
	if calls != 2 {
		t.Fatal("queries unexpectedly shared transport")
	}
}
