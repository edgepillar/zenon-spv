// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/fetch"
)

type collectionCLITransport func(*http.Request) (*http.Response, error)

func (f collectionCLITransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func collectionCLIArgs(t *testing.T) ([]string, []json.RawMessage) {
	t.Helper()
	raw, err := os.ReadFile("../../internal/testdata/conformance/candidate-v3-node-rpc.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if len(raw) != 15475 || hex.EncodeToString(digest[:]) != "4ac2da237eead98f146d931a27679a7251a5a9ef5e109920b9f7fd1f3a383e57" {
		t.Fatal("recorded RPC fixture changed")
	}
	var capture struct {
		Rows []struct {
			Wire   string `json:"wire_json"`
			Signed bool   `json:"existing_signature_valid"`
		}
	}
	if json.Unmarshal(raw, &capture) != nil || len(capture.Rows) < 3 {
		t.Fatal("RPC fixture shape")
	}
	var rows []json.RawMessage
	var anchor, header, tip string
	for i, row := range capture.Rows[:3] {
		if !row.Signed {
			t.Fatal("expected original public signature")
		}
		value, err := fetch.DecodeCandidateV3Momentum([]byte(row.Wire))
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, json.RawMessage(row.Wire))
		if i == 0 {
			anchor = hex.EncodeToString(value.Header.Header.PreviousHash[:])
		}
		if i == 1 {
			header = hex.EncodeToString(value.Header.Header.HeaderHash[:])
		}
		if i == 2 {
			tip = hex.EncodeToString(value.Header.Header.HeaderHash[:])
		}
	}
	return []string{"--rpc", "https://selected.invalid", "--chain-id", "100", "--anchor-height", "11", "--anchor-hash", anchor, "--height", "13", "--header-hash", header, "--tip-height", "14", "--tip-hash", tip, "--domain-id", "1", "--batch-id", "1"}, rows
}

func collectionCLIReplace(args []string, name, value string) []string {
	out := append([]string(nil), args...)
	for i := 0; i+1 < len(out); i++ {
		if out[i] == "--"+name {
			out[i+1] = value
			return out
		}
	}
	return append(out, "--"+name, value)
}

func collectionCLIClient(t *testing.T, rows []json.RawMessage, mode string, methods *[]string) func(string) *fetch.Client {
	t.Helper()
	return func(endpoint string) *fetch.Client {
		if endpoint != "https://selected.invalid" {
			t.Fatal("explicit endpoint changed or environment used")
		}
		client := fetch.NewClient(endpoint)
		var selectedDeadline time.Time
		client.HTTP.Transport = collectionCLITransport(func(req *http.Request) (*http.Response, error) {
			deadline, ok := req.Context().Deadline()
			if !ok || !selectedDeadline.IsZero() && !deadline.Equal(selectedDeadline) {
				t.Fatal("selected reads did not share one overall deadline")
			}
			selectedDeadline = deadline
			var call struct {
				Method string
				Params []json.RawMessage
			}
			if json.NewDecoder(req.Body).Decode(&call) != nil {
				t.Fatal("request")
			}
			*methods = append(*methods, call.Method)
			if mode == "failure" {
				return nil, errors.New("PRIVATE_RPC_URL PRIVATE_PAYLOAD")
			}
			var result any
			switch call.Method {
			case "ledger.getMomentumsByHeight":
				result = map[string]any{"list": rows, "count": 3}
			case "ledger.getProof":
				result = map[string]any{"root": strings.Repeat("0", 64), "value": nil, "proof": make([]byte, 99)}
			default:
				t.Fatal("unexpected method")
			}
			raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
			if err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
		})
		return client
	}
}

func TestExperimentalCollectionCLIExplicitEndpoint(t *testing.T) {
	t.Setenv("ZENON_SPV_RPC", "https://PRIVATE_ENV.invalid")
	t.Setenv("ZENON_SPV_PEERS", "https://PRIVATE_PEERS.invalid")
	args, rows := collectionCLIArgs(t)
	var output, diagnostics bytes.Buffer
	var methods []string
	code := runExperimentalCollection(context.Background(), args, &output, &diagnostics, collectionCLIClient(t, rows, "", &methods))
	var doc map[string]json.RawMessage
	if code != 0 || diagnostics.Len() != 0 || json.Unmarshal(output.Bytes(), &doc) != nil || len(doc) != 3 || len(methods) != 2 {
		t.Fatal("collection did not complete its explicit candidate-only document")
	}
	if _, ok := doc["gateway"]; ok {
		t.Fatal("unselected frontier request added")
	}
	if bytes.Contains(output.Bytes(), []byte("PRIVATE")) {
		t.Fatal("private source leaked")
	}
	// Full-width typed selectors remain valid; no JavaScript number path.
	args = collectionCLIReplace(args, "domain-id", "4294967295")
	args = collectionCLIReplace(args, "batch-id", "18446744073709551615")
	args = append(args, "--timeout", "10s")
	output.Reset()
	diagnostics.Reset()
	methods = nil
	if runExperimentalCollection(context.Background(), args, &output, &diagnostics, collectionCLIClient(t, rows, "", &methods)) != 0 {
		t.Fatal("full-width selector truncated")
	}
}

func TestExperimentalCollectionCLIArgumentsBeforeClient(t *testing.T) {
	base, _ := collectionCLIArgs(t)
	cases := map[string][]string{"missing": {}, "positional": append(append([]string{}, base...), "PRIVATE_POSITIONAL"), "unknown": append(append([]string{}, base...), "--PRIVATE_ARGUMENT=PRIVATE_VALUE"), "repeated-comparison": append(append([]string{}, base...), "--compare-gateway", "--compare-gateway=false")}
	for i := 0; i < len(base); i += 2 {
		name := strings.TrimPrefix(base[i], "--")
		cases["missing/"+name] = append(append([]string{}, base[:i]...), base[i+2:]...)
		cases["repeated/"+name] = append(append([]string{}, base...), base[i], base[i+1])
	}
	for name, values := range map[string][]string{
		"rpc":      {"", "file:///PRIVATE", "relative", "https://host.invalid/#PRIVATE"},
		"chain-id": {"0", "1", "18446744073709551616"}, "domain-id": {"4294967296", "-1"}, "batch-id": {"18446744073709551616", "-1"},
		"height": {"0", "11", "15"}, "tip-height": {"10", "11"}, "anchor-height": {"0", "18446744073709551615"},
		"timeout": {"0s", "-1s", "10m1s", "PRIVATE_DURATION"}, "anchor-hash": {"PRIVATE_HASH", strings.Repeat("0", 64), strings.Repeat("A", 64)},
		"header-hash": {"PRIVATE_HASH", strings.Repeat("0", 64)}, "tip-hash": {"PRIVATE_HASH", strings.Repeat("0", 64)},
	} {
		for _, value := range values {
			cases[name+"/"+value] = collectionCLIReplace(base, name, value)
		}
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			called := false
			code := runExperimentalCollection(context.Background(), args, &output, &diagnostics, func(string) *fetch.Client { called = true; return nil })
			if code != 64 || called || output.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE") {
				t.Fatal("invalid selector reached client or ordinary output")
			}
		})
	}
	var output, diagnostics bytes.Buffer
	if runExperimentalCollection(context.Background(), []string{"--help"}, &output, &diagnostics, nil) != 0 || !strings.Contains(output.String(), "Usage:") || diagnostics.Len() != 0 {
		t.Fatal("help performed input or network work")
	}
}

type collectionShortOutput struct{ writes int }

func (w *collectionShortOutput) Write(raw []byte) (int, error) { w.writes++; return len(raw) - 1, nil }

func TestExperimentalCollectionCLICompletion(t *testing.T) {
	args, rows := collectionCLIArgs(t)
	var output, diagnostics bytes.Buffer
	var methods []string
	if code := runExperimentalCollection(context.Background(), args, &output, &diagnostics, collectionCLIClient(t, rows, "failure", &methods)); code != 1 || output.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE") {
		t.Fatal("transport failure leaked data or became success")
	}
	writer := &collectionShortOutput{}
	diagnostics.Reset()
	methods = nil
	if code := runExperimentalCollection(context.Background(), args, writer, &diagnostics, collectionCLIClient(t, rows, "", &methods)); code != 70 || writer.writes != 1 {
		t.Fatal("short output was retried or accepted")
	}
	output.Reset()
	diagnostics.Reset()
	methods = nil
	// Cancellation is explicit: a 1ns timer callback need not run before the
	// first read on every native scheduler. No sleep or timer precision claim.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := runExperimentalCollection(ctx, args, &output, &diagnostics, collectionCLIClient(t, rows, "", &methods)); code != 1 || output.Len() != 0 || len(methods) != 0 {
		t.Fatal("cancelled collection progressed")
	}
}
