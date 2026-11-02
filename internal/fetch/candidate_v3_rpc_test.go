// SPDX-License-Identifier: MIT

package fetch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestCandidateV3RPCSelectedRange(t *testing.T) {
	rows := candidateRPCRows(t)
	for _, kind := range []string{"recorded", "short", "wrong-height", "bad-row", "null", "wrapper-id"} {
		t.Run(kind, func(t *testing.T) {
			client := NewClient("https://candidate.invalid")
			client.HTTP.Transport = diagnosticTransport(func(req *http.Request) (*http.Response, error) {
				var call struct {
					Method string   `json:"method"`
					Params []uint64 `json:"params"`
				}
				if json.NewDecoder(req.Body).Decode(&call) != nil || call.Method != "ledger.getMomentumsByHeight" || !reflect.DeepEqual(call.Params, []uint64{12, 3}) {
					t.Error("caller-selected range changed")
				}
				members := []json.RawMessage{json.RawMessage(rows[0].Wire), json.RawMessage(rows[1].Wire), json.RawMessage(rows[2].Wire)}
				switch kind {
				case "short":
					members = members[:2]
				case "wrong-height":
					members[0] = members[1]
				case "bad-row":
					members[2] = json.RawMessage(`{}`)
				}
				var result any = map[string]any{"list": members, "count": 3}
				if kind == "null" {
					result = nil
				}
				id := 1
				if kind == "wrapper-id" {
					id = 2
				}
				raw := candidateRPCJSON(t, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})
			got, err := client.FetchCandidateV3ByHeight(context.Background(), 12, 3)
			if kind != "recorded" {
				if err == nil || got != nil {
					t.Fatal("unusable range returned partial candidates", err)
				}
				return
			}
			if err != nil || len(got) != 3 {
				t.Fatal("recorded range", err)
			}
			for i, row := range got {
				if row.Header.Header.Height != uint64(12+i) || row.Header.StateRoot.IsZero() {
					t.Fatal("range identity or root lost")
				}
			}
		})
	}
	client := NewClient("https://candidate.invalid")
	calls := 0
	client.HTTP.Transport = diagnosticTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("request must not be sent")
	})
	for _, query := range [][2]uint64{{0, 1}, {12, 0}, {12, 4097}, {^uint64(0), 2}} {
		if got, err := client.FetchCandidateV3ByHeight(context.Background(), query[0], query[1]); !errors.Is(err, ErrInvalidQuery) || got != nil {
			t.Fatal("invalid query reached transport", err)
		}
	}
	if calls != 0 {
		t.Fatal("invalid query sent a request")
	}
}

func TestCandidateV3RPCPaginationUsesOneRange(t *testing.T) {
	base := candidateRPCRows(t)[3] // Explicitly unsigned transport-only fixture.
	decoded, err := DecodeCandidateV3Momentum([]byte(base.Wire))
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient("https://candidate.invalid")
	calls := [][2]uint64{}
	client.HTTP.Transport = diagnosticTransport(func(req *http.Request) (*http.Response, error) {
		var request struct {
			Params [2]uint64 `json:"params"`
		}
		if json.NewDecoder(req.Body).Decode(&request) != nil {
			t.Fatal("request decode")
		}
		calls = append(calls, request.Params)
		members := make([]json.RawMessage, 0, request.Params[1])
		for i := uint64(0); i < request.Params[1]; i++ {
			h := decoded.Header
			h.Header.Height = request.Params[0] + i
			h.Header.HeaderHash, _ = h.ComputeHash()
			fields := candidateRPCFields(t, base.Wire)
			fields["height"] = candidateRPCJSON(t, h.Header.Height)
			fields["hash"] = candidateRPCJSON(t, hashHex(h.Header.HeaderHash))
			members = append(members, candidateRPCJSON(t, fields))
		}
		raw := candidateRPCJSON(t, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"list": members}})
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})
	got, err := client.FetchCandidateV3ByHeight(context.Background(), 12, 1025)
	if err != nil || len(got) != 1025 || !reflect.DeepEqual(calls, [][2]uint64{{12, 1024}, {1036, 1}}) || got[1024].Header.Header.Height != 1036 {
		t.Fatal("pagination changed the selected range", err)
	}
}

func TestCandidateV3RPCWholeRangeByteBudget(t *testing.T) {
	rows := candidateRPCRows(t)
	for _, extra := range []int{0, 1} {
		client := NewClient("https://candidate.invalid")
		body := candidateRPCJSON(t, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"list": []json.RawMessage{json.RawMessage(rows[0].Wire)}}})
		padded := append(bytes.Repeat([]byte{' '}, int(MaxCandidateV3RangeBytes)-len(body)+extra), body...)
		client.HTTP.Transport = diagnosticTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(padded))}, nil
		})
		got, err := client.FetchCandidateV3ByHeight(context.Background(), 12, 1)
		if extra == 0 {
			if err != nil || len(got) != 1 {
				t.Fatal("exact candidate range byte limit", err)
			}
		} else if !errors.Is(err, ErrResponseTooLarge) || got != nil {
			t.Fatal("oversized candidate response accepted", err)
		}
	}
	base := rows[3]
	decoded, err := DecodeCandidateV3Momentum([]byte(base.Wire))
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient("https://candidate.invalid")
	calls := 0
	client.HTTP.Transport = diagnosticTransport(func(req *http.Request) (*http.Response, error) {
		var request struct {
			Params [2]uint64 `json:"params"`
		}
		if json.NewDecoder(req.Body).Decode(&request) != nil {
			t.Fatal("request decode")
		}
		calls++
		members := make([]json.RawMessage, 0, request.Params[1])
		for i := uint64(0); i < request.Params[1]; i++ {
			h := decoded.Header
			h.Header.Height = request.Params[0] + i
			h.Header.HeaderHash, _ = h.ComputeHash()
			fields := candidateRPCFields(t, base.Wire)
			fields["height"] = candidateRPCJSON(t, h.Header.Height)
			fields["hash"] = candidateRPCJSON(t, hashHex(h.Header.HeaderHash))
			members = append(members, candidateRPCJSON(t, fields))
		}
		body := candidateRPCJSON(t, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"list": members}})
		if calls == 1 {
			body = append(bytes.Repeat([]byte{' '}, int(MaxCandidateV3RangeBytes)-len(body)-1), body...)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
	})
	got, err := client.FetchCandidateV3ByHeight(context.Background(), 12, 1025)
	if calls != 2 || !errors.Is(err, ErrResponseTooLarge) || got != nil {
		t.Fatal("second page reset the shared byte budget or published a prefix", err)
	}
}
