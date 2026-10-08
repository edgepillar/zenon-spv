package fetch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRPCErrorDataValuesPreserveOutcome(t *testing.T) {
	for name, data := range map[string]string{
		"null":   `null`,
		"bool":   `false`,
		"number": `-12.5e+2`,
		"string": `"escaped \\\" slash \\ newline \n"`,
		"array":  `[null,true,1,"text",{"data":0,"data":1}]`,
		"object": `{"code":null,"message":1,"data":[],"nested":[{},[]]}`,
		"large":  `{"detail":"` + strings.Repeat("x", 1<<20) + `"}`,
	} {
		for _, field := range []string{`data`, `d\u0061ta`} {
			for _, first := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/first=%t", name, field, first), func(t *testing.T) {
					if !json.Valid([]byte(data)) {
						t.Fatal("invalid positive fixture")
					}
					member := `"` + field + `":` + data
					controls := `"code":-1,"message":"private-data-marker","trace":true,"trace":null`
					body := controls + `,` + member
					if first {
						body = member + `,` + controls
					}
					r, err := decodeRPCResponse([]byte(`{"jsonrpc":"2.0","id":1,"error":{`+body+`}}`), 1)
					if err != nil || len(r.Result) != 0 || r.Error == nil ||
						r.Error.Code != -1 || r.Error.Message != "private-data-marker" {
						t.Fatalf("optional data changed remote error: %v", err)
					}
					if r.Error.Error() != "rpc error -1" {
						t.Fatal("ordinary error diagnostic echoed remote text")
					}
				})
			}
		}
	}
}

func TestCallRejectsMalformedErrorDataBeforeOutput(t *testing.T) {
	for name, data := range map[string]string{
		"missing":        ``,
		"array comma":    `[1,]`,
		"object colon":   `{"key" 1}`,
		"object comma":   `{"key":1,}`,
		"string escape":  `"\q"`,
		"string control": "\"private-data-marker\x01\"",
		"number zero":    `01`,
		"number suffix":  `1e`,
		"wrong close":    `[{]}`,
		"truncated":      `{"key":[1`,
		"depth exceeded": strings.Repeat("[", 10001) + `null` + strings.Repeat("]", 10001),
	} {
		t.Run(name, func(t *testing.T) {
			raw := `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"private-data-marker","data":` + data + `}}`
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
					t.Fatalf("malformed optional data supplied an outcome: %v", err)
				}
				if strings.Contains(err.Error(), "private-data-marker") || strings.Contains(err.Error(), server.URL) {
					t.Fatal("parser diagnostic echoed peer data")
				}
			}
		})
	}
}

func TestRPCErrorDataCannotHideControlFailures(t *testing.T) {
	large := `{"detail":"` + strings.Repeat("x", 1<<20) + `"}`
	for name, body := range map[string]string{
		"duplicate null":    `"code":-1,"message":"failure","data":null,"data":` + large,
		"duplicate array":   `"code":-1,"message":"failure","data":[],"data":` + large,
		"duplicate object":  `"code":-1,"message":"failure","data":{},"data":` + large,
		"escaped duplicate": `"code":-1,"message":"failure","data":` + large + `,"d\u0061ta":null`,
		"escaped first":     `"d\u0061ta":` + large + `,"code":-1,"message":"failure","data":null`,
		"alias before":      `"Data":` + large + `,"code":-1,"message":"failure","data":null`,
		"alias after":       `"data":` + large + `,"code":-1,"message":"failure","DATA":null`,
		"alias only":        `"code":-1,"message":"failure","dAtA":` + large,
		"missing code":      `"message":"failure","data":` + large,
		"missing message":   `"code":-1,"data":` + large,
		"null code":         `"code":null,"data":` + large + `,"message":"failure"`,
		"null message":      `"code":-1,"data":` + large + `,"message":null`,
		"code alias":        `"code":-1,"data":` + large + `,"Code":0,"message":"failure"`,
		"message duplicate": `"code":-1,"message":"failure","data":` + large + `,"message":"replacement"`,
	} {
		t.Run(name, func(t *testing.T) {
			r, err := decodeRPCResponse([]byte(`{"jsonrpc":"2.0","id":1,"error":{`+body+`}}`), 1)
			if !errors.Is(err, ErrInvalidRPCResponse) || len(r.Result) != 0 || r.Error != nil {
				t.Fatalf("optional data hid a control failure: %v", err)
			}
			if strings.Contains(err.Error(), "private-data-marker") {
				t.Fatal("parser diagnostic echoed discarded data")
			}
		})
	}
}

func TestRPCErrorDataStillConsumesBodyBudget(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"private-data-marker","data":{"detail":"` + strings.Repeat("x", 32<<10) + `"}}}`
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = fmt.Fprint(w, raw)
	}))
	defer server.Close()
	client := NewClient(server.URL)
	for _, limit := range []int64{int64(len(raw)) - 1, int64(len(raw))} {
		budget := &rpcResponseBudget{remaining: limit}
		out := json.RawMessage(`"unchanged"`)
		err := client.callWithBudget(context.Background(), "test", []any{}, &out, budget)
		if string(out) != `"unchanged"` {
			t.Fatal("remote error changed caller output")
		}
		if limit < int64(len(raw)) {
			if !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("optional data bypassed the body limit: %v", err)
			}
		} else {
			var remote *rpcError
			if !errors.As(err, &remote) || remote.Code != -1 || remote.Message != "private-data-marker" || budget.remaining != 0 {
				t.Fatalf("remote error body was not fully charged: %v", err)
			}
			if err := client.callWithBudget(context.Background(), "test", []any{}, nil, budget); !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("error outcome restored the consumed budget: %v", err)
			}
		}
	}
	if requests.Load() != 2 {
		t.Fatal("exhausted shared budget performed another request")
	}
}
