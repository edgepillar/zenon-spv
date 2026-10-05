package fetch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestRPCValidExtensionsPreserveOutcomes(t *testing.T) {
	for name, extension := range map[string]string{
		"null":   `null`,
		"bool":   `false`,
		"number": `-12.5e+2`,
		"string": `"escaped \\\" slash \\ newline \n"`,
		"array":  `[null,true,1,"text",{"result":3}]`,
		"object": `{"id":99,"error":{"code":null},"nested":[{},[]]}`,
		"large":  `"` + strings.Repeat("x", 1<<20) + `"`,
	} {
		t.Run(name, func(t *testing.T) {
			if !json.Valid([]byte(extension)) {
				t.Fatal("invalid positive fixture")
			}
			// Unknown duplicate names are allowed, including escaped names.
			// Nested names do not become envelope control fields.
			raw := `{"trace":` + extension + `,"result":{"value":2},"id":1,"jsonrpc":"2.0","tr\u0061ce":null}`
			r, err := decodeRPCResponse([]byte(raw), 1)
			if err != nil || string(r.Result) != `{"value":2}` || r.Error != nil {
				t.Fatalf("extension changed result: %v", err)
			}
			raw = `{"jsonrpc":"2.0","trace":` + extension + `,"id":1,"error":{"trace":` + extension + `,"code":0,"message":"failure","data":null,"trace":false}}`
			r, err = decodeRPCResponse([]byte(raw), 1)
			if err != nil || len(r.Result) != 0 || r.Error == nil || r.Error.Code != 0 || r.Error.Message != "failure" {
				t.Fatalf("extension changed remote error: %v", err)
			}
		})
	}
}

func TestCallRejectsMalformedExtensionsBeforeOutput(t *testing.T) {
	for name, extension := range map[string]string{
		"missing":        ``,
		"array comma":    `[1,]`,
		"object colon":   `{"key" 1}`,
		"object comma":   `{"key":1,}`,
		"string escape":  `"\q"`,
		"string control": "\"bad\x01text\"",
		"number zero":    `01`,
		"number suffix":  `1e`,
		"wrong close":    `[{]}`,
		"truncated":      `{"key":[1`,
		"depth exceeded": strings.Repeat("[", 10001) + `null` + strings.Repeat("]", 10001),
	} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/error=%t", name, nested), func(t *testing.T) {
				raw := `{"jsonrpc":"2.0","id":1,"result":{"value":2},"private-extension-marker":` + extension + `}`
				if nested {
					raw = `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"failure","private-extension-marker":` + extension + `}}`
				}
				if json.Valid([]byte(raw)) {
					t.Fatal("valid negative fixture")
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, raw) }))
				defer server.Close()
				client := NewClient(server.URL)
				out := json.RawMessage(`"unchanged"`)
				for _, target := range []any{&out, nil} {
					err := client.Call(context.Background(), "test", []any{}, target)
					if !errors.Is(err, ErrInvalidRPCResponse) || string(out) != `"unchanged"` {
						t.Fatalf("malformed extension supplied evidence: %v", err)
					}
					if strings.Contains(err.Error(), "private-extension-marker") || strings.Contains(err.Error(), server.URL) {
						t.Fatal("parser diagnostic echoed peer data")
					}
				}
			})
		}
	}
}

func TestLargeRPCExtensionCannotHideControlFailures(t *testing.T) {
	extension := `"` + strings.Repeat("x", 1<<20) + `"`
	for name, raw := range map[string]string{
		"wrong id":             `{"jsonrpc":"2.0","trace":` + extension + `,"id":2,"result":0}`,
		"duplicate escaped id": `{"jsonrpc":"2.0","id":2,"trace":` + extension + `,"\u0069d":1,"result":0}`,
		"duplicate result":     `{"jsonrpc":"2.0","id":1,"result":0,"trace":` + extension + `,"result":1}`,
		"case alias":           `{"jsonrpc":"2.0","id":1,"trace":` + extension + `,"Result":0,"result":1}`,
		"both outcomes":        `{"jsonrpc":"2.0","id":1,"result":0,"trace":` + extension + `,"error":{"code":-1,"message":"failure"}}`,
		"error alias":          `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"trace":` + extension + `,"Code":0,"message":"failure"}}`,
		"duplicate data":       `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"data":null,"trace":` + extension + `,"data":0,"message":"failure"}}`,
		"trailing data":        `{"jsonrpc":"2.0","id":1,"trace":` + extension + `,"result":0} true`,
	} {
		t.Run(name, func(t *testing.T) {
			r, err := decodeRPCResponse([]byte(raw), 1)
			if !errors.Is(err, ErrInvalidRPCResponse) || len(r.Result) != 0 || r.Error != nil {
				t.Fatalf("large extension hid control failure: %v", err)
			}
		})
	}
}

func TestRPCExtensionsStillConsumeBodyBudget(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"result":2,"trace":"` + strings.Repeat("x", 32<<10) + `"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, raw) }))
	defer server.Close()
	client := NewClient(server.URL)
	for _, limit := range []int64{int64(len(raw)) - 1, int64(len(raw))} {
		budget := &rpcResponseBudget{remaining: limit}
		out := 7
		err := client.callWithBudget(context.Background(), "test", []any{}, &out, budget)
		if limit < int64(len(raw)) {
			if !errors.Is(err, ErrResponseTooLarge) || out != 7 {
				t.Fatalf("ignored extension bypassed byte budget: %v", err)
			}
		} else if err != nil || out != 2 || budget.remaining != 0 {
			t.Fatalf("exact-size body was not fully charged: %v", err)
		}
	}
}

func TestRPCExtensionPreservesCapturedAccountBlock(t *testing.T) {
	raw, err := os.ReadFile("testdata/mainnet_account_block.json")
	if err != nil {
		t.Fatal(err)
	}
	var captured struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &captured); err != nil || len(captured.Result) == 0 {
		t.Fatalf("captured result: %v", err)
	}
	body := append([]byte(`{"jsonrpc":"2.0","trace":{"metadata":"`+strings.Repeat("x", 1<<20)+`"},"id":1,"result":`), captured.Result...)
	body = append(body, '}')
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer server.Close()
	var result json.RawMessage
	if err := NewClient(server.URL).Call(context.Background(), "ledger.getAccountBlocksByHeight", []any{}, &result); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, captured.Result) {
		t.Fatal("extension changed captured result bytes")
	}
	var list struct {
		List []rpcAccountBlock `json:"list"`
	}
	if err := json.Unmarshal(result, &list); err != nil || len(list.List) != 1 {
		t.Fatalf("captured block list: %v", err)
	}
	block, err := convertAndVerifyAccountBlock(list.List[0])
	const expected = "01e4877c8273f16a9ad21a1e28a96a88e142d59aec0ac9a46a312c0301cda50c"
	if err != nil || fmt.Sprintf("%x", block.BlockHash) != expected {
		t.Fatalf("captured hash recomputation changed: %v", err)
	}
}
