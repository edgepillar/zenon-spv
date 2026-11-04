// SPDX-License-Identifier: MIT

package fetch

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestCandidateBatchContextCollectionKeysAndCompletion(t *testing.T) {
	for _, mode := range []string{"complete", "missing-1", "missing-2", "missing-3", "oversize-1", "oversize-2", "oversize-3", "transport-2", "malformed-3"} {
		t.Run(mode, func(t *testing.T) {
			rows, selected := collectionFixture(t)
			client, _ := collectionClient(t, rows, selected, "")
			original := client.HTTP.Transport
			proofs := 0
			client.HTTP.Transport = diagnosticTransport(func(request *http.Request) (*http.Response, error) {
				raw, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				request.Body = io.NopCloser(bytes.NewReader(raw))
				var call struct {
					Method string
					Params []json.RawMessage
				}
				if json.Unmarshal(raw, &call) != nil {
					t.Fatal("call encoding")
				}
				if call.Method != "ledger.getProof" {
					return original.RoundTrip(request)
				}
				proofs++
				var height uint64
				var key []byte
				if len(call.Params) != 2 || json.Unmarshal(call.Params[0], &height) != nil || json.Unmarshal(call.Params[1], &key) != nil || height != 13 {
					t.Fatal("proof height changed")
				}
				suffix := []string{"02000000010000000000000001", "0100000001", "1500000001"}[proofs-1]
				if hex.EncodeToString(key) != "0301b3b6e5adcb4d0cad7fcef33598c6318c6318c004"+suffix {
					t.Fatal("locally derived full key changed")
				}
				// Transport controls only: these well-framed candidate bytes do
				// not match a header/root or establish typed value acceptance.
				var result any = map[string]any{"root": strings.Repeat("0", 64), "value": nil, "proof": make([]byte, 99)}
				if mode == "missing-"+string(rune('0'+proofs)) {
					result = nil
				}
				if mode == "malformed-"+string(rune('0'+proofs)) {
					result = map[string]any{"proof": nil}
				}
				if mode == "transport-"+string(rune('0'+proofs)) {
					return nil, errors.New("fixture transport failure")
				}
				body := collectionReply(t, result)
				if mode == "oversize-"+string(rune('0'+proofs)) {
					body = append(bytes.Repeat([]byte(" "), int(MaxCandidateStateResponseBytes)), body...)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
			})
			doc, err := client.FetchCandidateBatchContextBundle(context.Background(), selected, false)
			if mode != "complete" {
				if err == nil || doc != nil {
					t.Fatal("later error returned partial document")
				}
				return
			}
			var output struct {
				Version   uint32
				Momentums []json.RawMessage
				Witnesses map[string]json.RawMessage
			}
			if err != nil || proofs != 3 || json.Unmarshal(doc, &output) != nil || output.Version != 1 || len(output.Momentums) != 3 || len(output.Witnesses) != 3 ||
				!reflect.DeepEqual(sortedContextKeys(output.Witnesses), []string{"batch_entry", "domain_config", "domain_record"}) {
				t.Fatal("three selected reads incomplete", err)
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(doc, &fields) != nil || len(fields) != 3 || fields["witness"] != nil {
				t.Fatal("legacy schema mixed into context bundle")
			}
		})
	}
}

func sortedContextKeys(values map[string]json.RawMessage) []string {
	var names []string
	for _, name := range []string{"batch_entry", "domain_config", "domain_record"} {
		if _, ok := values[name]; ok {
			names = append(names, name)
		}
	}
	return names
}

func TestCandidateBatchContextCollectionPreflight(t *testing.T) {
	_, selected := collectionFixture(t)
	client := NewClient("https://unused.invalid")
	calls := 0
	client.HTTP.Transport = diagnosticTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("must not call") })
	for _, kind := range []string{"domain-zero", "invalid-height", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			s := selected
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "domain-zero":
				s.DomainID = 0
			case "invalid-height":
				s.Height = 0
			case "canceled":
				cancel()
			}
			if raw, err := client.FetchCandidateBatchContextBundle(ctx, s, false); err == nil || raw != nil || calls != 0 {
				t.Fatal("selection reached transport")
			}
		})
	}
}
