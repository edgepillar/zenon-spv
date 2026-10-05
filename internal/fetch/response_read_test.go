package fetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
)

type responseReadSource struct {
	input    *bytes.Reader
	chunk    int
	terminal error
	zeros    int
	closed   bool
}

func (r *responseReadSource) Read(p []byte) (int, error) {
	if r.zeros > 0 {
		r.zeros--
		return 0, nil
	}
	if r.chunk > 0 && len(p) > r.chunk {
		p = p[:r.chunk]
	}
	n, err := r.input.Read(p)
	if r.input.Len() == 0 && r.terminal != nil {
		return n, r.terminal
	}
	return n, err
}

func (r *responseReadSource) Close() error { r.closed = true; return nil }

func TestRPCResponseReadContract(t *testing.T) {
	t.Run("bytes_and_single_overflow_probe", func(t *testing.T) {
		for _, limit := range []int{0, 1, 511, 512, 513, 4096, 32768} {
			for _, size := range []int{0, max(0, limit-1), limit, limit + 1, limit + 17} {
				input := bytes.Repeat([]byte{0x91}, size)
				for _, chunk := range []int{0, 7} {
					for _, terminal := range []error{nil, io.EOF} {
						actual := &responseReadSource{input: bytes.NewReader(input), chunk: chunk, terminal: terminal, zeros: 2}
						reference := &responseReadSource{input: bytes.NewReader(input), chunk: chunk, terminal: terminal, zeros: 2}
						want, wantErr := io.ReadAll(io.LimitReader(reference, int64(limit)+1))
						got, err := readRPCBody(actual, int64(limit))
						if err != wantErr || !bytes.Equal(got, want) || actual.input.Len() != reference.input.Len() || cap(got) > limit+1 {
							t.Fatalf("bounded reference mismatch: limit=%d size=%d chunk=%d err=%v", limit, size, chunk, err)
						}
					}
				}
			}
		}
	})
	t.Run("simultaneous_data_and_read_errors", func(t *testing.T) {
		failure := errors.New(privateDiagnosticMarker)
		for _, limit := range []int{0, 1, 511, 512, 513, 4096} {
			for _, size := range []int{0, limit, limit + 1, limit + 17} {
				input := bytes.Repeat([]byte{'x'}, size)
				for _, terminal := range []error{failure, context.Canceled, context.DeadlineExceeded, io.ErrUnexpectedEOF} {
					for _, chunk := range []int{0, 7} {
						actual := &responseReadSource{input: bytes.NewReader(input), chunk: chunk, terminal: terminal}
						reference := &responseReadSource{input: bytes.NewReader(input), chunk: chunk, terminal: terminal}
						want, wantErr := io.ReadAll(io.LimitReader(reference, int64(limit)+1))
						got, err := readRPCBody(actual, int64(limit))
						if err != wantErr || !bytes.Equal(got, want) || actual.input.Len() != reference.input.Len() || cap(got) > limit+1 {
							t.Fatalf("read error changed: limit=%d size=%d chunk=%d got=%v want=%v", limit, size, chunk, err, wantErr)
						}
					}
				}
			}
		}
	})
	t.Run("complete_call_boundaries_and_private_errors", func(t *testing.T) {
		raw := []byte(`{"jsonrpc":"2.0","id":1,"trace":"` + strings.Repeat("x", 2048) + `","result":2}`)
		failure := errors.New(privateDiagnosticMarker)
		for _, limit := range []int{0, len(raw) - 1, len(raw), len(raw) + 1} {
			for _, terminal := range []error{nil, io.EOF, failure, context.Canceled, context.DeadlineExceeded} {
				for _, chunk := range []int{0, 7} {
					body := &responseReadSource{input: bytes.NewReader(raw), chunk: chunk, terminal: terminal}
					requests := 0
					client := NewClient("https://rpc.invalid")
					client.HTTP.Transport = diagnosticTransport(func(*http.Request) (*http.Response, error) {
						requests++
						return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
					})
					budget := &rpcResponseBudget{remaining: int64(limit)}
					out := 99
					err := client.callWithBudget(context.Background(), "test", nil, &out, budget)
					if limit == 0 {
						if !errors.Is(err, ErrResponseTooLarge) || requests != 0 || out != 99 || body.closed {
							t.Fatal("exhausted budget reached transport or output", err)
						}
						continue
					}
					if requests != 1 || !body.closed || strings.Contains(fmt.Sprintf("%v %+v", err, err), privateDiagnosticMarker) {
						t.Fatal("call replayed, leaked its cause or did not close the body")
					}
					if terminal != nil && terminal != io.EOF {
						if !errors.Is(err, terminal) || out != 99 || budget.remaining != int64(limit) {
							t.Fatal("complete or overflowing JSON hid a read error", err)
						}
					} else if limit < len(raw) {
						want := fmt.Sprintf("%s: read %d bytes, remaining %d", ErrResponseTooLarge, len(raw), limit)
						if !errors.Is(err, ErrResponseTooLarge) || err.Error() != want || out != 99 || budget.remaining != int64(limit) {
							t.Fatal("overflow classification, output or budget changed", err)
						}
					} else if err != nil || out != 2 || budget.remaining != int64(limit-len(raw)) {
						t.Fatal("successful response or accounting changed", err)
					}
					if body.input.Len() != len(raw)-min(len(raw), limit+1) {
						t.Fatal("call consumed more than the one-byte overflow probe")
					}
				}
			}
		}
	})
	t.Run("content_length_does_not_change_policy", func(t *testing.T) {
		raw := []byte(`{"jsonrpc":"2.0","id":1,"result":2}`)
		for _, hint := range []int64{-1, 0, 1, int64(len(raw)), MaxResponseBytes, math.MaxInt64} {
			body := &responseReadSource{input: bytes.NewReader(raw)}
			client := NewClient("https://rpc.invalid")
			client.HTTP.Transport = diagnosticTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: body, ContentLength: hint, Header: make(http.Header)}, nil
			})
			budget := &rpcResponseBudget{remaining: int64(len(raw))}
			var out int
			if err := client.callWithBudget(context.Background(), "test", nil, &out, budget); err != nil || out != 2 || budget.remaining != 0 || !body.closed {
				t.Fatalf("peer length metadata changed the read: hint=%d err=%v", hint, err)
			}
		}
	})
	t.Run("shared_range_budget_and_whole_json_validation", func(t *testing.T) {
		raw := `{"jsonrpc":"2.0","id":1,"result":2}`
		client := NewClient("https://rpc.invalid")
		client.HTTP.Transport = diagnosticTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(raw)), Header: make(http.Header)}, nil
		})
		budget := &rpcResponseBudget{remaining: int64(2*len(raw) - 1)}
		var out int
		if err := client.callWithBudget(context.Background(), "test", nil, &out, budget); err != nil || out != 2 || budget.remaining != int64(len(raw)-1) {
			t.Fatal("first response did not consume the shared budget", err)
		}
		out = 99
		if err := client.callWithBudget(context.Background(), "test", nil, &out, budget); !errors.Is(err, ErrResponseTooLarge) || out != 99 || budget.remaining != int64(len(raw)-1) {
			t.Fatal("second response reset the shared budget", err)
		}
		for _, bad := range []string{raw + " null", raw[:len(raw)-1], `{"jsonrpc":"2.0","id":1,"result":2,"result":3}`} {
			raw = bad
			out = 99
			if err := client.Call(context.Background(), "test", nil, &out); !errors.Is(err, ErrInvalidRPCResponse) || out != 99 {
				t.Fatal("changed read buffer accepted malformed or ambiguous JSON", err)
			}
		}
	})
}

func FuzzRPCResponseRead(f *testing.F) {
	for _, seed := range []string{"", "x", "{}", strings.Repeat("x", 512), `{"result":2} trailing`} {
		f.Add([]byte(seed), uint16(len(seed)), uint8(0), false)
	}
	f.Fuzz(func(t *testing.T, input []byte, limit uint16, chunk uint8, failure bool) {
		if len(input) > 8192 {
			t.Skip()
		}
		maxBytes := int64(limit % 4097)
		terminal := io.EOF
		if failure {
			terminal = io.ErrUnexpectedEOF
		}
		actual := &responseReadSource{input: bytes.NewReader(input), chunk: int(chunk % 8), terminal: terminal}
		reference := &responseReadSource{input: bytes.NewReader(input), chunk: int(chunk % 8), terminal: terminal}
		want, wantErr := io.ReadAll(io.LimitReader(reference, maxBytes+1))
		got, err := readRPCBody(actual, maxBytes)
		if err != wantErr || !bytes.Equal(got, want) || actual.input.Len() != reference.input.Len() || int64(cap(got)) > maxBytes+1 {
			t.Fatal("bounded read contract changed", err, wantErr)
		}
	})
}
