package fetch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// BenchmarkRPCResponseRead compares a complete Client.Call, including request
// creation, body reading, envelope validation and result decoding. The parent
// call body is captured below; only its receiver is adapted to a free function.
// Fixture construction is outside timing. No live HTTP connection is used.
func BenchmarkRPCResponseRead(b *testing.B) {
	node, err := os.ReadFile("testdata/mainnet_account_block.json")
	if err != nil {
		b.Fatal(err)
	}
	var captured struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(node, &captured); err != nil || len(captured.Result) == 0 {
		b.Fatal("missing node result", err)
	}
	type sample struct {
		name   string
		body   []byte
		result []byte
	}
	samples := []sample{{"node_account", node, captured.Result}}
	for _, size := range []int{32 << 10, 1 << 20, 8 << 20} {
		samples = append(samples, sample{fmt.Sprintf("%d", size), []byte(`{"jsonrpc":"2.0","id":1,"trace":"` + strings.Repeat("x", size) + `","result":2}`), []byte("2")})
	}
	for _, input := range samples {
		for _, mode := range []struct {
			name string
			call func(*Client, context.Context, string, any, any, *rpcResponseBudget) error
		}{
			{"read_all_reference", callWithReadAllReference},
			{"bounded_growth", func(c *Client, ctx context.Context, method string, params any, out any, budget *rpcResponseBudget) error {
				return c.callWithBudget(ctx, method, params, out, budget)
			}},
		} {
			b.Run(input.name+"/"+mode.name, func(b *testing.B) {
				client := NewClient("https://rpc.invalid")
				client.HTTP.Transport = diagnosticTransport(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(input.body)), Header: make(http.Header)}, nil
				})
				ctx := context.Background()
				b.ReportAllocs()
				b.SetBytes(int64(len(input.body)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var out json.RawMessage
					budget := newRPCResponseBudget()
					if err := mode.call(client, ctx, "test", nil, &out, budget); err != nil || !bytes.Equal(out, input.result) || budget.remaining != MaxResponseBytes-int64(len(input.body)) {
						b.Fatal("result or byte budget mismatch", err)
					}
				}
			})
		}
	}
}

// Exact parent body from eb8ad113adf94d4d3819e1260a79a65c1aa36fe4;
// this test-only reference uses the current unchanged envelope/result decoders.
func callWithReadAllReference(c *Client, ctx context.Context, method string, params any, out any, budget *rpcResponseBudget) error {
	if budget.remaining <= 0 {
		return ErrResponseTooLarge
	}
	request := rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params}
	body, err := json.Marshal(request)
	if err != nil {
		return callFailure("marshal request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return callFailure("new request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Keep the selected endpoint fixed without mutating the supplied client.
	// Share its transport, timeout and cookie jar, but refuse every redirect.
	// ErrUseLastResponse lets the normal status check close the response body
	// and report only its status, without copying Location into diagnostics.
	httpClient := *c.HTTP
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return callFailure("post", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rpc http %d", resp.StatusCode)
	}
	// D2: cap the body at the remaining range budget. Read one extra byte
	// so we can distinguish "exactly at limit" from "exceeded limit".
	raw, err := io.ReadAll(io.LimitReader(resp.Body, budget.remaining+1))
	if err != nil {
		return callFailure("read body", err)
	}
	if int64(len(raw)) > budget.remaining {
		return fmt.Errorf("%w: read %d bytes, remaining %d", ErrResponseTooLarge, len(raw), budget.remaining)
	}
	budget.remaining -= int64(len(raw))
	r, err := decodeRPCResponse(raw, request.ID)
	if err != nil {
		return err
	}
	if r.Error != nil {
		return r.Error
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(r.Result, out); err != nil {
		return callFailure("unmarshal result", err)
	}
	return nil
}
