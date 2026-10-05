package fetch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCallRejectsUnboundEnvelopeBeforeOutput(t *testing.T) {
	for name, raw := range map[string]string{
		"wrong id":          `{"jsonrpc":"2.0","id":2,"result":{"value":2}}`,
		"missing version":   `{"id":1,"result":{"value":2}}`,
		"duplicate result":  `{"jsonrpc":"2.0","id":1,"result":{"value":1},"result":{"value":2}}`,
		"overwritten error": `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unavailable"},"error":null,"result":{"value":2}}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, raw) }))
			defer server.Close()
			client := NewClient(server.URL)
			out := struct {
				Value int `json:"value"`
			}{Value: 7}
			if err := client.Call(context.Background(), "test", []any{}, &out); !errors.Is(err, ErrInvalidRPCResponse) || out.Value != 7 {
				t.Fatalf("invalid envelope changed output: value=%d err=%v", out.Value, err)
			}
			if err := client.Call(context.Background(), "test", []any{}, nil); !errors.Is(err, ErrInvalidRPCResponse) {
				t.Fatal("nil output bypassed envelope validation")
			}
		})
	}
}

func TestWrongEnvelopeCannotSupplyMomentum(t *testing.T) {
	result := map[string]any{"list": []any{emptyContentMomentum(10)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 2, "result": result})
	}))
	defer server.Close()
	got, err := NewClient(server.URL).FetchByHeight(context.Background(), 10, 1)
	if !errors.Is(err, ErrInvalidRPCResponse) || len(got) != 0 {
		t.Fatalf("wrong response id supplied momentum evidence: n=%d err=%v", len(got), err)
	}
}

func invalidRPCEnvelopes() map[string]string {
	return map[string]string{
		"empty": ``, "null": `null`, "array": `[]`, "scalar": `1`,
		"no fields": `{}`, "missing id": `{"jsonrpc":"2.0","result":0}`,
		"null id":                  `{"jsonrpc":"2.0","id":null,"result":0}`,
		"string id":                `{"jsonrpc":"2.0","id":"1","result":0}`,
		"fractional id":            `{"jsonrpc":"2.0","id":1.5,"result":0}`,
		"decimal id":               `{"jsonrpc":"2.0","id":1.0,"result":0}`,
		"exponent id":              `{"jsonrpc":"2.0","id":1e0,"result":0}`,
		"large id":                 `{"jsonrpc":"2.0","id":18446744073709551616,"result":0}`,
		"boolean id":               `{"jsonrpc":"2.0","id":true,"result":0}`,
		"wrong version":            `{"jsonrpc":"1.0","id":1,"result":0}`,
		"numeric version":          `{"jsonrpc":2.0,"id":1,"result":0}`,
		"null version":             `{"jsonrpc":null,"id":1,"result":0}`,
		"neither outcome":          `{"jsonrpc":"2.0","id":1}`,
		"both outcomes":            `{"jsonrpc":"2.0","id":1,"result":null,"error":{"code":-1,"message":"failure"}}`,
		"null error beside result": `{"jsonrpc":"2.0","id":1,"result":0,"error":null}`,
		"null error":               `{"jsonrpc":"2.0","id":1,"error":null}`,
		"empty error":              `{"jsonrpc":"2.0","id":1,"error":{}}`,
		"array error":              `{"jsonrpc":"2.0","id":1,"error":[]}`,
		"missing code":             `{"jsonrpc":"2.0","id":1,"error":{"message":"failure"}}`,
		"missing message":          `{"jsonrpc":"2.0","id":1,"error":{"code":0}}`,
		"null code":                `{"jsonrpc":"2.0","id":1,"error":{"code":null,"message":"failure"}}`,
		"null message":             `{"jsonrpc":"2.0","id":1,"error":{"code":0,"message":null}}`,
		"fractional code":          `{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"failure"}}`,
		"string code":              `{"jsonrpc":"2.0","id":1,"error":{"code":"0","message":"failure"}}`,
		"numeric message":          `{"jsonrpc":"2.0","id":1,"error":{"code":0,"message":1}}`,
		"duplicate id":             `{"jsonrpc":"2.0","id":2,"id":1,"result":0}`,
		"duplicate escaped id":     `{"jsonrpc":"2.0","id":2,"\u0069d":1,"result":0}`,
		"duplicate version":        `{"jsonrpc":"1.0","jsonrpc":"2.0","id":1,"result":0}`,
		"duplicate code":           `{"jsonrpc":"2.0","id":1,"error":{"code":1,"code":2,"message":"failure"}}`,
		"duplicate message":        `{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"a","message":"b"}}`,
		"duplicate error data":     `{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"failure","data":0,"data":1}}`,
		"case alias":               `{"jsonrpc":"2.0","id":1,"result":0,"Result":1}`,
		"error case alias":         `{"jsonrpc":"2.0","id":1,"error":{"code":1,"Code":2,"message":"failure"}}`,
		"trailing object":          `{"jsonrpc":"2.0","id":1,"result":0}{}`,
		"trailing text":            `{"jsonrpc":"2.0","id":1,"result":0} private-response-marker`,
		"truncated":                `{"jsonrpc":"2.0","id":1,"result":`,
		"private value":            `{"jsonrpc":"private-response-marker","id":1,"result":0}`,
		"private field":            `{"jsonrpc":"2.0","id":1,"result":0,"private-response-marker":}`,
	}
}

func TestDecodeRPCEnvelopeRejectsMalformedControlFields(t *testing.T) {
	for name, raw := range invalidRPCEnvelopes() {
		t.Run(name, func(t *testing.T) {
			r, err := decodeRPCResponse([]byte(raw), 1)
			if !errors.Is(err, ErrInvalidRPCResponse) || len(r.Result) != 0 || r.Error != nil {
				t.Fatalf("malformed envelope returned evidence: result=%s remote_error=%v err=%v", r.Result, r.Error, err)
			}
			if strings.Contains(err.Error(), "private-response-marker") {
				t.Fatal("parser error echoed peer data")
			}
		})
	}
}

func TestCallPreservesValidResultsAndRemoteErrors(t *testing.T) {
	for _, result := range []string{`null`, `0`, `false`, `"value"`, `[1,2]`, `{"value":2}`} {
		t.Run(result, func(t *testing.T) {
			raw := `{"trace":{"extension":true},"result":` + result + `,"id":1,"jsonrpc":"2.0"}`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, raw) }))
			defer server.Close()
			var out json.RawMessage
			client := NewClient(server.URL)
			if err := client.Call(context.Background(), "test", []any{}, &out); err != nil || string(out) != result {
				t.Fatalf("valid result changed: result=%s err=%v", out, err)
			}
			if err := client.Call(context.Background(), "test", []any{}, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":0,"message":"failure","data":{"detail":1},"trace":true}}`)
	}))
	defer server.Close()
	out := json.RawMessage(`"unchanged"`)
	for _, target := range []any{&out, nil} {
		err := NewClient(server.URL).Call(context.Background(), "test", []any{}, target)
		var remote *rpcError
		if !errors.As(err, &remote) || remote.Code != 0 || remote.Message != "failure" || string(out) != `"unchanged"` {
			t.Fatalf("valid remote error was lost: out=%s err=%v", out, err)
		}
	}
}

func FuzzRPCEnvelope(f *testing.F) {
	for _, raw := range invalidRPCEnvelopes() {
		f.Add(raw)
	}
	f.Add(`{"jsonrpc":"2.0","id":1,"result":null}`)
	f.Add(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"failure"}}`)
	f.Add(`{"trace":{"nested":[null,true,"escaped \\ text"]},"jsonrpc":"2.0","id":1,"result":null,"trace":0}`)
	f.Add(`{"jsonrpc":"2.0","id":1,"result":null,"trace":[1,]}`)
	f.Add(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"trace":{"key":},"message":"failure"}}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		r, err := decodeRPCResponse([]byte(raw), 1)
		if err != nil {
			if !errors.Is(err, ErrInvalidRPCResponse) || len(r.Result) != 0 || r.Error != nil {
				t.Fatal("failed decode returned partial evidence")
			}
			return
		}
		var envelope struct {
			Version string `json:"jsonrpc"`
			ID      int    `json:"id"`
		}
		if json.Unmarshal([]byte(raw), &envelope) != nil || envelope.Version != "2.0" || envelope.ID != 1 {
			t.Fatal("accepted an unbound response")
		}
		if (len(r.Result) == 0) == (r.Error == nil) {
			t.Fatal("accepted an ambiguous outcome")
		}
	})
}
