//go:build candidate_dispatcher

// SPDX-License-Identifier: GPL-3.0-only
// Call the actual HTTP codec/dispatcher entirely in memory with read-only delegates.
package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common/types"
	"github.com/zenon-network/go-zenon/rpc/api"
	"github.com/zenon-network/go-zenon/rpc/server"
)

func init() { rpcDispatcherGenerator = generateRPCDispatcher }

type dispatcherInput struct {
	Name          string         `json:"name"`
	MethodCase    rpcMethodInput `json:"method_case"`
	HTTPMethod    string         `json:"http_method"`
	ContentType   string         `json:"content_type"`
	ContentLength int64          `json:"declared_content_length"`
	Request       string         `json:"request_json"`
}

type readOnlyLedger struct {
	actual *api.LedgerApi
	calls  []map[string]any
}

// Do not embed LedgerApi: only these two exported read-only callbacks are exposed.
func (r *readOnlyLedger) GetProof(height uint64, key []byte) (*api.StateProof, error) {
	r.calls = append(r.calls, map[string]any{"method": "GetProof", "height": height, "key_hex": rpcOptionalHex(key)})
	return r.actual.GetProof(height, key)
}
func (r *readOnlyLedger) GetStateRoot(height uint64) (types.Hash, error) {
	r.calls = append(r.calls, map[string]any{"method": "GetStateRoot", "height": height})
	return r.actual.GetStateRoot(height)
}

func dispatcherJSON(value any) string {
	rawValue, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(rawValue)
}
func dispatcherRequest(id, method, params string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":%q,"params":%s}`, id, method, params)
}
func dispatcherInputs() []dispatcherInput {
	rows := []dispatcherInput{}
	for _, item := range rpcInputs() {
		method := "ledger.getStateRoot"
		params := fmt.Sprintf("[%d]", item.Height)
		if item.Method == "GetProof" {
			method, params = "ledger.getProof", fmt.Sprintf("[%d,%s]", item.Height, dispatcherJSON(rpcSelectedKey(item.KeyKind)))
		}
		rows = append(rows, dispatcherInput{"method/" + item.Name, item, "POST", "application/json", -1,
			dispatcherRequest("7", method, params)})
	}
	base := rpcInputs()[6] // Independently selected active-three synthetic proof case.
	params := "[42," + dispatcherJSON(rpcSelectedKey("balance")) + "]"
	request := dispatcherRequest("7", "ledger.getProof", params)
	key := dispatcherJSON(rpcSelectedKey("balance"))
	for _, name := range []string{"string-id", "null-id", "boolean-id", "fraction-id", "exponent-id", "wide-id", "object-id", "array-id",
		"notification", "unknown-method", "unknown-namespace", "missing-version", "wrong-version", "unknown-field", "duplicate-id", "duplicate-params",
		"trailing-object", "trailing-garbage", "malformed-json", "null-request", "empty-batch", "single-call-batch", "empty-body",
		"missing-params", "null-params", "named-params", "missing-key", "excess-params", "null-height", "negative-height", "fraction-height",
		"exponent-height", "text-height", "boolean-height", "max-height", "overflow-height", "null-key", "array-key", "bad-base64", "unpadded-base64",
		"invalid-byte-array", "wrong-content-type", "put-method", "health-get", "declared-oversize", "options-method"} {
		row := dispatcherInput{"codec/" + name, base, "POST", "application/json", -1, request}
		switch name {
		case "string-id", "null-id", "boolean-id", "fraction-id", "exponent-id", "wide-id", "object-id", "array-id":
			id := map[string]string{"string-id": `"selected-7"`, "null-id": "null", "boolean-id": "true", "fraction-id": "7.0", "exponent-id": "7e0", "wide-id": "9007199254740993", "object-id": "{}", "array-id": "[]"}[name]
			row.Request = dispatcherRequest(id, "ledger.getProof", params)
		case "notification":
			row.Request = strings.Replace(request, `"id":7,`, "", 1)
		case "unknown-method":
			row.Request = dispatcherRequest("7", "ledger.unknown", params)
		case "unknown-namespace":
			row.Request = dispatcherRequest("7", "other.getProof", params)
		case "missing-version":
			row.Request = strings.Replace(request, `"jsonrpc":"2.0",`, "", 1)
		case "wrong-version":
			row.Request = strings.Replace(request, `"jsonrpc":"2.0"`, `"jsonrpc":"1.0"`, 1)
		case "unknown-field":
			row.Request = strings.Replace(request, `"jsonrpc":`, `"unselected":true,"jsonrpc":`, 1)
		case "duplicate-id":
			row.Request = strings.Replace(request, `"id":7`, `"id":8,"id":7`, 1)
		case "duplicate-params":
			row.Request = strings.Replace(request, `"params":`, `"params":[0,null],"params":`, 1)
		case "trailing-object":
			row.Request += " {}"
		case "trailing-garbage":
			row.Request += " trailing"
		case "malformed-json":
			row.Request = `{"jsonrpc":`
		case "null-request":
			row.Request = "null"
		case "empty-batch":
			row.Request = "[]"
		case "single-call-batch":
			row.Request = "[" + request + "]"
		case "empty-body":
			row.Request = ""
		case "missing-params":
			row.Request = `{"jsonrpc":"2.0","id":7,"method":"ledger.getProof"}`
		case "null-params", "named-params", "missing-key", "excess-params":
			p := map[string]string{"null-params": "null", "named-params": `{"height":42,"key":` + key + `}`, "missing-key": "[42]", "excess-params": "[42," + key + ",0]"}[name]
			row.Request = dispatcherRequest("7", "ledger.getProof", p)
		case "null-height", "negative-height", "fraction-height", "exponent-height", "text-height", "boolean-height", "max-height", "overflow-height":
			h := map[string]string{"null-height": "null", "negative-height": "-1", "fraction-height": "42.0", "exponent-height": "4.2e1", "text-height": `"42"`, "boolean-height": "true", "max-height": "18446744073709551615", "overflow-height": "18446744073709551616"}[name]
			row.Request = dispatcherRequest("7", "ledger.getProof", "["+h+","+key+"]")
		case "null-key", "array-key", "bad-base64", "unpadded-base64", "invalid-byte-array":
			k := map[string]string{"null-key": "null", "array-key": strings.ReplaceAll(fmt.Sprint(rpcSelectedKey("balance")), " ", ","), "bad-base64": `"!"`, "unpadded-base64": `"AA"`, "invalid-byte-array": "[300]"}[name]
			row.Request = dispatcherRequest("7", "ledger.getProof", "[42,"+k+"]")
		case "wrong-content-type":
			row.ContentType = "text/plain"
		case "put-method":
			row.HTTPMethod = "PUT"
		case "health-get":
			row.HTTPMethod, row.ContentType, row.Request = "GET", "", ""
		case "declared-oversize":
			row.ContentLength = 5*1024*1024 + 1
		case "options-method":
			row.HTTPMethod, row.ContentType = "OPTIONS", ""
		}
		rows = append(rows, row)
	}
	return rows
}

func generateRPCDispatcher() any {
	rows := []any{}
	for _, input := range dispatcherInputs() {
		item := input.MethodCase
		key := rpcSelectedKey(item.KeyKind)
		root, value, proof := rpcPrimitive(key, rpcLeafValue(item.BindingName))
		momentum := &nom.Momentum{Version: item.Version, ChainIdentifier: 2, PreviousHash: hash(strings.Repeat("55", 32)),
			Height: item.StoreHeight, TimestampUnix: 1700000000, ChangesHash: hash(strings.Repeat("66", 32)), NextFusionPrice: 7, NextWorkPrice: 11, StateRoot: root}
		momentum.Hash = momentum.ComputeHash()
		if item.HashOverride {
			momentum.Hash = hash(strings.Repeat("aa", 32))
		}
		c := &recordingRPCChain{value: value, proof: proof, root: root,
			lookupErr: rpcStubError(item.LookupError, -32101), proofErr: rpcStubError(item.ProofError, -32102), rootErr: rpcStubError(item.RootError, -32103)}
		switch item.ResponseKind {
		case "coherent-substitution":
			c.root, c.value, c.proof = rpcPrimitive(key, raw(fmt.Sprintf("%064x", 2)))
		case "nil-value":
			c.value = nil
		case "oversized-value":
			// Preserve the previous method fixture's fixed 4097-byte counterexample.
			c.root, c.value, c.proof = rpcPrimitive(key, []byte(strings.Repeat("w", 4097)))
		case "root-substitution":
			c.root = hash(strings.Repeat("44", 32))
		}
		c.store = &recordingRPCStore{chain: c, momentum: momentum}
		var selectedMomentum any = map[string]any{"version": momentum.Version, "height": momentum.Height, "hash": momentum.Hash.String(), "state_root": momentum.StateRoot.String()}
		if item.Missing {
			c.store.momentum, selectedMomentum = nil, nil
		}
		delegate := &readOnlyLedger{actual: api.NewLedgerApi(&recordingRPCZenon{chain: c}), calls: []map[string]any{}}
		actual := server.NewServer()
		if err := actual.RegisterName("ledger", delegate); err != nil {
			panic(err)
		}
		// NewRequest and NewRecorder use in-memory objects; neither creates a listener.
		request := httptest.NewRequest(input.HTTPMethod, "/", strings.NewReader(input.Request))
		request.Header.Set("Content-Type", input.ContentType)
		if input.ContentLength >= 0 {
			request.ContentLength = input.ContentLength
		}
		recorder := httptest.NewRecorder()
		actual.ServeHTTP(recorder, request)
		actual.Stop()
		if err := request.Body.Close(); err != nil {
			panic(err)
		}
		rows = append(rows, map[string]any{"input": input, "momentum": selectedMomentum, "delegated_calls": delegate.calls,
			"trace": c.trace, "http_status": recorder.Code, "response_content_type": recorder.Header().Get("Content-Type"), "response_body": recorder.Body.String()})
	}
	return map[string]any{"format_version": 1, "kind": "candidate-rpc-dispatcher-research",
		"source": map[string]string{"repository": "https://github.com/digitalSloth/go-zenon", "revision": nodeCommit, "tree": nodeTree},
		"scope": map[string]bool{"synthetic": true, "unsigned": true, "LedgerApi_constructor_executed": true, "LedgerApi_methods_executed": true,
			"recording_chain_store_stubs": true, "primitive_proof_api_executed": true, "StateProof_serializer_executed": true,
			"rpc_dispatcher_executed": true, "rpc_parameter_decoder_executed": true, "rpc_http_handler_executed_in_memory": true,
			"read_only_delegates_only": true, "server_stopped_after_each_case": true, "request_body_closed_after_each_case": true,
			"http_listener_started": false, "live_transport_executed": false, "actual_chain_stateTree_executed": false, "node_database_opened": false,
			"node_lifecycle_executed": false, "node_tests_executed": false, "profile_agreed": false, "network_activation_authenticated": false,
			"header_authentication_executed": false, "runtime_state_proof_acceptance": false}, "cases": rows}
}
