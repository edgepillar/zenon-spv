package fetch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A peer must not select another endpoint or replay the caller's query there.
// Relative and same-origin redirects also require an explicit URL selection.
func TestRPCRejectsRedirects(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, relative := range []bool{false, true} {
			for _, custom := range []bool{false, true} {
				t.Run(fmt.Sprintf("status=%d/relative=%t/custom-client=%t", status, relative, custom), func(t *testing.T) {
					var selectedCalls, destinationCalls, replayedQueries, callbackCalls atomic.Int32
					respond := func(w http.ResponseWriter, r *http.Request) {
						destinationCalls.Add(1)
						body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
						if err != nil {
							t.Error("redirect destination could not read its request")
						}
						if r.Method == http.MethodPost && strings.Contains(string(body), privateDiagnosticMarker) {
							replayedQueries.Add(1)
						}
						_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"redirected"}`)
					}
					destination := httptest.NewServer(http.HandlerFunc(respond))
					t.Cleanup(destination.Close)
					location := destination.URL + "/destination?secret=" + privateDiagnosticMarker
					if relative {
						location = "/destination?secret=" + privateDiagnosticMarker
					}
					selected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != "/selected" {
							respond(w, r)
							return
						}
						selectedCalls.Add(1)
						var request rpcRequest
						if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&request) != nil || request.Method != "test" {
							t.Error("selected peer did not receive the original JSON-RPC query")
						}
						w.Header().Set("Location", location)
						w.WriteHeader(status)
						_, _ = io.WriteString(w, privateDiagnosticMarker)
					}))
					t.Cleanup(selected.Close)
					client := NewClient(selected.URL + "/selected?secret=" + privateDiagnosticMarker)
					if custom {
						client.HTTP = &http.Client{Transport: client.HTTP.Transport, Timeout: 2 * time.Second,
							CheckRedirect: func(*http.Request, []*http.Request) error {
								callbackCalls.Add(1)
								return nil
							}}
					}
					t.Cleanup(client.HTTP.CloseIdleConnections)
					out := "unchanged"
					err := client.Call(context.Background(), "test", []string{privateDiagnosticMarker}, &out)
					if err == nil || err.Error() != fmt.Sprintf("rpc http %d", status) || out != "unchanged" {
						t.Errorf("redirect did not retain its safe HTTP failure and untouched output: error=%v output=%q", err, out)
					}
					if selectedCalls.Load() != 1 || destinationCalls.Load() != 0 || callbackCalls.Load() != 0 {
						t.Errorf("redirect reached an unselected endpoint or caller callback: destination requests=%d replayed queries=%d", destinationCalls.Load(), replayedQueries.Load())
					}
					if custom && client.HTTP.CheckRedirect(nil, nil) != nil {
						t.Error("RPC call mutated the supplied HTTP client's redirect policy")
					}
				})
			}
		}
	}
}

func TestRPCDirectResponseAndMalformedRedirect(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("malformed-redirect=%t", malformed), func(t *testing.T) {
			var calls atomic.Int32
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				if malformed {
					w.Header().Set("Location", "http://"+privateDiagnosticMarker+"%zz.invalid")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"direct"}`)
			}))
			t.Cleanup(peer.Close)
			client := NewClient(peer.URL)
			t.Cleanup(client.HTTP.CloseIdleConnections)
			out := "unchanged"
			err := client.Call(context.Background(), "test", nil, &out)
			if malformed {
				if err == nil || strings.Contains(err.Error(), privateDiagnosticMarker) || out != "unchanged" {
					t.Fatal("malformed Location disclosed peer text or changed output")
				}
			} else if err != nil || out != "direct" {
				t.Fatalf("direct JSON-RPC response failed: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatal("RPC call made an unexpected number of requests")
			}
		})
	}
}

type redirectResponseBody struct {
	io.Reader
	closed atomic.Int32
}

func (b *redirectResponseBody) Close() error { b.closed.Add(1); return nil }

func TestRPCRejectedRedirectClosesBody(t *testing.T) {
	var calls atomic.Int32
	body := &redirectResponseBody{Reader: strings.NewReader(privateDiagnosticMarker)}
	client := NewClient("https://selected.invalid/rpc")
	client.HTTP.Transport = diagnosticTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Request: r, Body: body,
			Header: http.Header{"Location": []string{"https://destination.invalid/" + privateDiagnosticMarker}}}, nil
	})
	err := client.Call(context.Background(), "test", nil, nil)
	if err == nil || err.Error() != "rpc http 307" || calls.Load() != 1 || body.closed.Load() != 1 {
		t.Fatalf("redirect refusal leaked its body or continued transport: %v", err)
	}
}
