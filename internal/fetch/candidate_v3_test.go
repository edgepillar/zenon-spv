// SPDX-License-Identifier: MIT

package fetch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

type candidateRPCRow struct {
	Name         string `json:"name"`
	Signed       bool   `json:"existing_signature_valid"`
	Wire         string `json:"wire_json"`
	DataHash     string `json:"data_hash"`
	ContentHash  string `json:"content_hash"`
	ContentBytes string `json:"content_bytes"`
	Preimage     string `json:"preimage"`
	Producer     string `json:"producer_raw_hex"`
}

func candidateRPCRows(t *testing.T) []candidateRPCRow {
	t.Helper()
	raw, err := os.ReadFile("../testdata/conformance/candidate-v3-node-rpc.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if len(raw) != 15475 || hex.EncodeToString(sum[:]) != "4ac2da237eead98f146d931a27679a7251a5a9ef5e109920b9f7fd1f3a383e57" {
		t.Fatal("source-bound RPC fixture changed")
	}
	var capture struct {
		Format  string            `json:"format"`
		Rows    []candidateRPCRow `json:"rows"`
		Harness struct {
			Path   string `json:"path"`
			Bytes  int    `json:"bytes"`
			SHA256 string `json:"sha256"`
		} `json:"harness"`
	}
	if err := json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	if capture.Format != "zenon-recorded-v3-rpc-source-fragments/v1" || len(capture.Rows) != 8 ||
		capture.Harness.Path != "tools/gen-state-root-vectors/candidate-v3-rpc-capture_test.go.txt" {
		t.Fatal("RPC fixture cohort or scope changed")
	}
	harness, err := os.ReadFile("../../" + capture.Harness.Path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(harness)
	if len(harness) != capture.Harness.Bytes || hex.EncodeToString(hash[:]) != capture.Harness.SHA256 {
		t.Fatal("recorded source capture harness changed")
	}
	return capture.Rows
}

func candidateRPCFields(t *testing.T, raw string) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func candidateRPCJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func candidateRPCRefused(t *testing.T, raw []byte) {
	t.Helper()
	got, err := DecodeCandidateV3Momentum(raw)
	if err != ErrCandidateV3Momentum || !reflect.DeepEqual(got, CandidateV3Momentum{}) {
		t.Fatal("invalid candidate must return the fixed diagnostic and no partial result", err)
	}
}

func TestCandidateV3MomentumRecordedNodeFragments(t *testing.T) {
	for _, row := range candidateRPCRows(t) {
		t.Run(row.Name, func(t *testing.T) {
			got, err := DecodeCandidateV3Momentum([]byte(row.Wire))
			if err != nil {
				t.Fatal(err)
			}
			h := got.Header.Header
			preimage, err := got.Header.Preimage()
			if err != nil || hex.EncodeToString(preimage[:]) != row.Preimage ||
				hashHex(h.DataHash) != row.DataHash || hashHex(h.ContentHash) != row.ContentHash ||
				hex.EncodeToString(got.Producer[:]) != row.Producer {
				t.Fatal("projection differs from source bytes and independent Python hash gate", err)
			}
			var content []byte
			for _, member := range got.Content {
				content = append(content, member.Bytes()...)
			}
			if hex.EncodeToString(content) != row.ContentBytes {
				t.Fatal("content sequence changed")
			}
			if ed25519.Verify(h.PublicKey, h.HeaderHash[:], h.Signature) != row.Signed {
				t.Fatal("fixture signature classification changed")
			}
			projected, err := json.Marshal(got.Header)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := chain.DecodeCandidateV3Header(projected)
			if err != nil || !reflect.DeepEqual(decoded, got.Header) {
				t.Fatal("projected codec mismatch", err)
			}
			if !errors.Is(chain.ValidateHeaderVersion(h.Version), chain.ErrUnsupportedHeaderVersion) {
				t.Fatal("candidate decoder must not enable production v3")
			}
		})
	}
}

func TestCandidateV3MomentumRequiresExactFields(t *testing.T) {
	row := candidateRPCRows(t)[4]
	for name := range candidateRPCFields(t, row.Wire) {
		for _, kind := range []string{"missing", "null", "duplicate", "case-alias"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				fields := candidateRPCFields(t, row.Wire)
				var raw []byte
				switch kind {
				case "missing":
					delete(fields, name)
				case "null":
					fields[name] = json.RawMessage("null")
				case "case-alias":
					fields[strings.ToUpper(name)] = fields[name]
					delete(fields, name)
				case "duplicate":
					base := candidateRPCJSON(t, fields)
					raw = append(append(base[:len(base)-1], ','), candidateRPCJSON(t, name)...)
					raw = append(raw, ':')
					raw = append(raw, fields[name]...)
					raw = append(raw, '}')
				}
				if raw == nil {
					raw = candidateRPCJSON(t, fields)
				}
				candidateRPCRefused(t, raw)
			})
		}
	}
}

func TestCandidateV3MomentumMalformedAndChangedValues(t *testing.T) {
	row := candidateRPCRows(t)[4]
	cases := map[string]map[string]any{
		"v1": {"version": 1}, "v2": {"version": 2}, "v4": {"version": 4},
		"changed-root": {"stateRoot": strings.Repeat("00", 32)}, "changed-data": {"data": "AQ=="},
		"changed-price": {"nextWorkPrice": 1001}, "changed-height": {"height": 15},
		"claimed-hash": {"hash": strings.Repeat("00", 32)}, "prefixed-hash": {"hash": "0x" + strings.Repeat("00", 32)},
		"uppercase-hash": {"stateRoot": strings.ToUpper("d99238e890b5c1e28d9272e94a2529518ee7bfd148cb9f13c2ea3473ee6d5d5a")},
		"short-key":      {"publicKey": "AQ=="}, "short-signature": {"signature": "AQ=="},
		"signature-padding": {"signature": strings.Repeat("A", 86)}, "data-padding": {"data": "AA"},
		"data-linebreak": {"data": "AA==\n"}, "data-pad-bits": {"data": "AB=="},
		"data-array": {"data": []int{0, 1}}, "content-object": {"content": map[string]any{}},
		"null-member": {"content": []any{nil}}, "nested-list": {"content": []any{[]any{}}},
		"prehashed-data": {"dataHash": strings.Repeat("00", 32)}, "prehashed-content": {"contentHash": strings.Repeat("00", 32)},
		"producer-claim":        {"producer": "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f"},
		"private-unknown-field": {"private-candidate-marker": "private-candidate-marker"},
	}
	for name, updates := range cases {
		t.Run(name, func(t *testing.T) {
			fields := candidateRPCFields(t, row.Wire)
			for k, v := range updates {
				fields[k] = candidateRPCJSON(t, v)
			}
			candidateRPCRefused(t, candidateRPCJSON(t, fields))
		})
	}
	for _, key := range []string{"version", "chainIdentifier", "height", "timestamp", "nextFusionPrice", "nextWorkPrice"} {
		for i, value := range []string{`-1`, `1.5`, `18446744073709551616`, `"3"`, `true`, `[]`} {
			t.Run(fmt.Sprintf("integer-%s-%d", key, i), func(t *testing.T) {
				fields := candidateRPCFields(t, row.Wire)
				fields[key] = json.RawMessage(value)
				candidateRPCRefused(t, candidateRPCJSON(t, fields))
			})
		}
	}
	for i, raw := range []string{"", "null", "[]", row.Wire + "{}", row.Wire + " private-candidate-marker", `{"jsonrpc":"2.0","result":` + row.Wire + `}`} {
		t.Run(fmt.Sprintf("document-%d", i), func(t *testing.T) { candidateRPCRefused(t, []byte(raw)) })
	}
}

func TestCandidateV3MomentumNestedSchemaAndOrder(t *testing.T) {
	rows := candidateRPCRows(t)
	base := candidateRPCFields(t, rows[4].Wire)
	var content []map[string]json.RawMessage
	if err := json.Unmarshal(base["content"], &content); err != nil {
		t.Fatal(err)
	}
	for name := range content[0] {
		for _, kind := range []string{"missing", "null", "duplicate"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				member := candidateRPCFields(t, string(candidateRPCJSON(t, content[0])))
				switch kind {
				case "missing":
					delete(member, name)
				case "null":
					member[name] = json.RawMessage("null")
				}
				raw := candidateRPCJSON(t, member)
				if kind == "duplicate" {
					raw = append(raw[:len(raw)-1], ',')
					raw = append(raw, candidateRPCJSON(t, name)...)
					raw = append(raw, ':')
					raw = append(raw, member[name]...)
					raw = append(raw, '}')
				}
				fields := candidateRPCFields(t, rows[4].Wire)
				fields["content"] = append(append([]byte{'['}, raw...), ']')
				candidateRPCRefused(t, candidateRPCJSON(t, fields))
			})
		}
	}
	for name, raw := range map[string]string{"extra": `{"address":"private-candidate-marker","height":1,"hash":"private-candidate-marker","extra":0}`, "invalid-address": `{"address":"private-candidate-marker","height":1,"hash":"` + strings.Repeat("00", 32) + `"}`, "fractional-height": `{"address":"z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f","height":1.5,"hash":"` + strings.Repeat("00", 32) + `"}`} {
		t.Run(name, func(t *testing.T) {
			fields := candidateRPCFields(t, rows[4].Wire)
			fields["content"] = json.RawMessage("[" + raw + "]")
			candidateRPCRefused(t, candidateRPCJSON(t, fields))
		})
	}
	fields := candidateRPCFields(t, rows[4].Wire)
	fields["content"] = candidateRPCJSON(t, []any{content[1], content[0]})
	candidateRPCRefused(t, candidateRPCJSON(t, fields))
	a, err := DecodeCandidateV3Momentum([]byte(rows[4].Wire))
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodeCandidateV3Momentum([]byte(rows[5].Wire))
	if err != nil {
		t.Fatal(err)
	}
	if a.Header.Header.ContentHash == b.Header.Header.ContentHash || a.Content[0] != b.Content[1] {
		t.Fatal("received content order must remain significant")
	}
}

func TestCandidateV3MomentumLimits(t *testing.T) {
	rows := candidateRPCRows(t)
	base := rows[0].Wire
	padded := append(bytes.Repeat([]byte{' '}, MaxCandidateV3MomentumJSONBytes-len(base)), base...)
	if _, err := DecodeCandidateV3Momentum(padded); err != nil {
		t.Fatal("exact document limit", err)
	}
	candidateRPCRefused(t, append(padded, ' '))
	for _, test := range []struct {
		field string
		count int
		hash  string
		ok    bool
	}{
		{"data", 16384, "93f8a552f83954e62eea37177eb10daba7cae12d2a736351632d8d518177c127", true},
		{"data", 16385, "d0a4ae4bcb10e7cc2308ba66fe3054a8890fda7f39e76a47d510ac81b9488d6a", false},
		{"content", 1024, "aea713f604ad9147d43471ee637e1b88c123fd45ee4eaa8ba109262dc02d765c", true},
		{"content", 1025, "fafd703833772863b4ceff5e9212f285a1d801429280f3ee7baf7a711fbe3aa5", false},
	} {
		t.Run(fmt.Sprintf("%s-%d", test.field, test.count), func(t *testing.T) {
			fields := candidateRPCFields(t, base)
			fields["hash"] = candidateRPCJSON(t, test.hash)
			if test.field == "data" {
				fields["data"] = candidateRPCJSON(t, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, test.count)))
			} else {
				var sourceMembers []json.RawMessage
				if err := json.Unmarshal(candidateRPCFields(t, rows[4].Wire)["content"], &sourceMembers); err != nil {
					t.Fatal(err)
				}
				members := make([]json.RawMessage, test.count)
				for i := range members {
					members[i] = sourceMembers[0]
				}
				fields["content"] = candidateRPCJSON(t, members)
			}
			raw := candidateRPCJSON(t, fields)
			if test.ok {
				if _, err := DecodeCandidateV3Momentum(raw); err != nil {
					t.Fatal("independently hashed exact limit", err)
				}
			} else {
				candidateRPCRefused(t, raw)
			}
		})
	}
}

func TestCandidateV3MomentumDetachedAndUnauthenticated(t *testing.T) {
	row := candidateRPCRows(t)[4]
	raw := []byte(row.Wire)
	a, err := DecodeCandidateV3Momentum(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodeCandidateV3Momentum(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = ' '
	}
	a.Header.Header.PublicKey[0] ^= 1
	a.Header.Header.Signature[0] ^= 1
	a.Content[0].Height++
	if reflect.DeepEqual(a, b) || hashHex(b.Header.Header.ContentHash) != row.ContentHash ||
		ed25519.Verify(b.Header.Header.PublicKey, b.Header.Header.HeaderHash[:], b.Header.Header.Signature) {
		t.Fatal("candidate values must be detached; encoding consistency must not imply valid signatures")
	}
}

func TestCandidateV3MomentumProductionFetchStillRefuses(t *testing.T) {
	row := candidateRPCRows(t)[0]
	client := NewClient("https://candidate.invalid")
	client.HTTP.Transport = diagnosticTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":` + row.Wire + `}`))}, nil
	})
	got, err := client.FetchFrontier(context.Background())
	if !errors.Is(err, chain.ErrUnsupportedHeaderVersion) || !reflect.DeepEqual(got, chain.Header{}) {
		t.Fatal("production fetch must still refuse v3", err)
	}
}
