package fetch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

const privateDiagnosticMarker = "private-rpc-marker"

type diagnosticTransport func(*http.Request) (*http.Response, error)

func (f diagnosticTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type diagnosticBody struct{ err error }

func (b diagnosticBody) Read([]byte) (int, error) { return 0, b.err }
func (b diagnosticBody) Close() error             { return nil }

type diagnosticCodec struct{ err error }

func (c diagnosticCodec) MarshalJSON() ([]byte, error) { return nil, c.err }
func (c *diagnosticCodec) UnmarshalJSON([]byte) error  { return c.err }

func TestRPCDiagnosticClassificationDoesNotEchoCause(t *testing.T) {
	for cause, want := range map[error]string{
		ErrQueryMismatch:                        "response does not match query",
		ErrInvalidRPCResponse:                   "invalid JSON-RPC response",
		ErrResponseTooComplex:                   "response exceeds decoded entry limit",
		ErrHashMismatch:                         "recomputed hash mismatch",
		chain.ErrUnsupportedHeaderVersion:       "unsupported momentum version",
		chain.ErrUnsupportedAccountBlockVersion: "unsupported account-block version",
		chain.ErrUnsupportedAccountBlockType:    "unsupported account-block type",
		chain.ErrInvalidAccountBlockEnvelope:    "invalid account-block envelope",
		chain.ErrInvalidAccountAmount:           "invalid account amount",
	} {
		wrapped := fmt.Errorf("%s: %w", privateDiagnosticMarker, cause)
		err := callFailure("unmarshal result", wrapped)
		if !errors.Is(err, cause) || strings.Contains(err.Error(), privateDiagnosticMarker) {
			t.Fatal("range classification lost its cause or disclosed peer data")
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatal("range classification was hidden from ordinary diagnostics")
		}
	}
}

func TestRPCDiagnosticPrivacyAndCausePreservation(t *testing.T) {
	for _, stage := range []string{"marshal", "URL parse", "transport", "read", "decode", "HTTP status", "RPC error", "cancel", "deadline", "timeout"} {
		t.Run(stage, func(t *testing.T) {
			endpoint := "https://user:" + privateDiagnosticMarker + "@" + privateDiagnosticMarker + ".invalid/path?token=" + privateDiagnosticMarker
			client := NewClient(endpoint)
			cause := errors.New(privateDiagnosticMarker)
			body := `{"jsonrpc":"2.0","id":1,"result":null}`
			status := http.StatusOK
			var params any = []any{}
			var decoded = json.RawMessage(`"unchanged"`)
			var output any = &decoded
			switch stage {
			case "marshal":
				params = diagnosticCodec{err: cause}
			case "URL parse":
				client.URL = "https://" + privateDiagnosticMarker + "%zz.invalid"
			case "decode":
				output = &diagnosticCodec{err: cause}
			case "HTTP status":
				status, body = http.StatusServiceUnavailable, privateDiagnosticMarker+"\n\x1b[31m"
			case "RPC error":
				body = `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"` + privateDiagnosticMarker + `"}}`
			case "cancel":
				cause = context.Canceled
			case "deadline":
				cause = context.DeadlineExceeded
			case "timeout":
				cause = os.ErrDeadlineExceeded
			}
			client.HTTP.Transport = diagnosticTransport(func(r *http.Request) (*http.Response, error) {
				user, pass, ok := r.BasicAuth()
				if !ok || user != "user" || pass != privateDiagnosticMarker || r.URL.Query().Get("token") != privateDiagnosticMarker {
					t.Error("diagnostic redaction changed the actual request")
				}
				if stage == "transport" || stage == "cancel" || stage == "deadline" || stage == "timeout" {
					return nil, cause
				}
				responseBody := io.NopCloser(strings.NewReader(body))
				if stage == "read" {
					responseBody = diagnosticBody{err: cause}
				}
				return &http.Response{StatusCode: status, Body: responseBody, Header: make(http.Header)}, nil
			})
			err := client.Call(context.Background(), "test", params, output)
			if err == nil || string(decoded) != `"unchanged"` {
				t.Fatal("failed call accepted or modified output")
			}
			formatted := fmt.Sprintf("%v %+v %s", err, err, err)
			if strings.Contains(formatted, privateDiagnosticMarker) || strings.Contains(formatted, "\x1b") {
				t.Error("ordinary error formatting disclosed private or peer-controlled text")
			}
			switch stage {
			case "URL parse":
				var parseError *url.Error
				if !errors.As(err, &parseError) {
					t.Error("URL parse error type was lost")
				}
			case "HTTP status":
				if !strings.Contains(formatted, "503") {
					t.Error("HTTP status was lost")
				}
			case "RPC error":
				var remote *rpcError
				if !errors.As(err, &remote) || remote.Code != -32000 || remote.Message != privateDiagnosticMarker || !strings.Contains(formatted, "-32000") {
					t.Error("structured RPC error was lost")
				}
			default:
				if !errors.Is(err, cause) {
					t.Error("underlying cause was lost")
				}
			}
		})
	}
}

func privatePeerURL(raw string) string {
	return strings.Replace(raw, "://", "://user:"+privateDiagnosticMarker+"@", 1) + "/" + privateDiagnosticMarker + "?token=" + privateDiagnosticMarker
}

func TestMultiPeerDiagnosticsUsePositions(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, privateDiagnosticMarker)
	}))
	t.Cleanup(dead.Close)
	for _, mode := range []string{"headers", "detailed", "accounts", "frontier"} {
		t.Run(mode, func(t *testing.T) {
			multi := NewMultiClient([]string{privatePeerURL(dead.URL), privatePeerURL(dead.URL) + "2"})
			var err error
			switch mode {
			case "headers":
				_, err = multi.FetchByHeight(context.Background(), 99, 1)
			case "detailed":
				_, err = multi.FetchByHeightDetailed(context.Background(), 99, 1)
			case "accounts":
				_, err = multi.FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, 1, 1)
			case "frontier":
				_, err = multi.FetchFrontierAtAgreedHeight(context.Background(), 0)
			}
			if !errors.Is(err, ErrNotEnoughPeers) || strings.Contains(err.Error(), privateDiagnosticMarker) || strings.Contains(err.Error(), dead.URL) {
				t.Error("quorum failure disclosed endpoint or remote response data")
			}
			if mode != "frontier" && (!strings.Contains(err.Error(), "peer[1]") || !strings.Contains(err.Error(), "peer[2]")) {
				t.Error("quorum error did not identify configured positions")
			}
		})
	}
	a, b := twoServers(t, func(m map[string]any) { m["signature"] = "AQ==" })
	multi := NewMultiClient([]string{privatePeerURL(a), privatePeerURL(b)})
	for _, detailed := range []bool{false, true} {
		var err error
		if detailed {
			_, err = multi.FetchByHeightDetailed(context.Background(), 99, 1)
		} else {
			_, err = multi.FetchByHeight(context.Background(), 99, 1)
		}
		if !errors.Is(err, ErrPeerDisagreement) || strings.Contains(err.Error(), privateDiagnosticMarker) || !strings.Contains(err.Error(), "peer[1]") || !strings.Contains(err.Error(), "peer[2]") {
			t.Error("disagreement disclosed endpoints or lost peer positions")
		}
	}
}
