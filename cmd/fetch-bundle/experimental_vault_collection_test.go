// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/fetch"
)

func TestExperimentalVaultCollection(t *testing.T) {
	const (
		path  = "5f65b0976c2db72c539d9099680b4e49eed4dc707c7ea3fc3a5eab0061932cfd"
		batch = "9007199254740993"
	)
	result := fmt.Sprintf(`{"domainId":1,"batchId":%s,"postStateRoot":"%s","verified":false,"proofs":[{"path":"%s","present":false,"value":null,"proof":"00%s%s"}]}`,
		batch, strings.Repeat("00", 32), path, path, strings.Repeat("00", 66))
	options := []string{"--domain-id", "1", "--batch-id", batch, "--contract-id", strings.Repeat("11", 32),
		"--account-hex", "00" + strings.Repeat("22", 19), "--token-standard-hex", strings.Repeat("33", 10)}
	for _, c := range []struct {
		name, body string
		code       int
	}{
		{"exact selection", `"result":` + result, 0},
		{"other batch", `"result":` + strings.Replace(result, batch, "9007199254740994", 1), 1},
		{"pruned batch", `"error":{"code":-32002,"message":"PRIVATE response text"}`, 2},
		{"unavailable", `"result":null`, 2},
		{"response limit", `"result":` + strings.Repeat(" ", fetch.MaxCandidateZenoStorageResultBytes+2048) + result, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				var req struct {
					JSONRPC string          `json:"jsonrpc"`
					Method  string          `json:"method"`
					ID      int             `json:"id"`
					Params  json.RawMessage `json:"params"`
				}
				if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil ||
					req.Method != "zeno_getProof" || req.JSONRPC != "2.0" || req.ID != 1 ||
					string(req.Params) != `[1,["`+path+`"],`+batch+`]` {
					t.Error("request differed from the selected numeric batch and path")
				}
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,`+c.body+"}")
			}))
			defer server.Close()
			args := append([]string{"--rpc", server.URL}, options...)
			var out, stderr bytes.Buffer
			code := runExperimentalVaultCollection(context.Background(), args, &out, &stderr, fetch.NewClient)
			if code != c.code || calls.Load() != 1 || strings.Contains(stderr.String(), "PRIVATE") {
				t.Fatal("unexpected collector completion", code, calls.Load(), stderr.String())
			}
			if code == 0 && (out.String() != result+"\n" || stderr.Len() != 0) || code != 0 && out.Len() != 0 {
				t.Fatal("collector exposed an incomplete or changed result")
			}
		})
	}
	var out, stderr bytes.Buffer
	noClient := func(string) *fetch.Client {
		t.Fatal("invalid selection reached transport")
		return nil
	}
	if code := runExperimentalVaultCollection(context.Background(), options, &out, &stderr, noClient); code != 64 || out.Len() != 0 {
		t.Fatal("missing endpoint was accepted")
	}
	options = append(options, "--rpc", "http://127.0.0.1:1", "--batch-id", "0")
	if code := runExperimentalVaultCollection(context.Background(), options, &out, &stderr, noClient); code != 64 || out.Len() != 0 {
		t.Fatal("duplicate batch option was accepted")
	}
}
