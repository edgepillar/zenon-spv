// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/fetch"
)

func TestExperimentalContextCollectionResumeCLI(t *testing.T) {
	base, rows := collectionCLIArgs(t)
	tip := ""
	for i := range base {
		if base[i] == "--tip-hash" {
			tip = base[i+1]
		}
	}
	args := append(append([]string(nil), base...), "--after-height", "14", "--after-hash", tip)
	var output, diagnostics bytes.Buffer
	var methods []string
	code := runExperimentalCollectionMode(context.Background(), args, &output, &diagnostics, collectionCLIClient(t, rows, "", &methods), true)
	var doc map[string]json.RawMessage
	if code != 0 || diagnostics.Len() != 0 || json.Unmarshal(output.Bytes(), &doc) != nil || string(doc["momentums"]) != "[]" || len(methods) != 3 {
		t.Fatal("explicit proof-only collection incomplete")
	}
	for _, method := range methods {
		if method != "ledger.getProof" {
			t.Fatal("proof-only continuation fetched original headers")
		}
	}
	output.Reset()
	diagnostics.Reset()
	if runExperimentalCollectionMode(context.Background(), []string{"--help"}, &output, &diagnostics, nil, true) != 0 || !strings.Contains(output.String(), "--after-height") || diagnostics.Len() != 0 {
		t.Fatal("context help omitted paired selectors")
	}
}

func TestExperimentalContextCollectionResumeCLIArguments(t *testing.T) {
	base, _ := collectionCLIArgs(t)
	tip := ""
	for i := range base {
		if base[i] == "--tip-hash" {
			tip = base[i+1]
		}
	}
	valid := append(append([]string(nil), base...), "--after-height", "14", "--after-hash", tip)
	cases := map[string][]string{
		"height-only":   append(append([]string(nil), base...), "--after-height", "14"),
		"hash-only":     append(append([]string(nil), base...), "--after-hash", tip),
		"repeat-height": append(append([]string(nil), valid...), "--after-height", "14"),
		"repeat-hash":   append(append([]string(nil), valid...), "--after-hash", tip),
	}
	for _, value := range []string{"0", "10", "15", "18446744073709551616", "-1", "PRIVATE_HEIGHT"} {
		cases["height/"+value] = collectionCLIReplace(valid, "after-height", value)
	}
	for _, value := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("1", 64), "PRIVATE_HASH"} {
		cases["hash/"+value] = collectionCLIReplace(valid, "after-hash", value)
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			called := false
			code := runExperimentalCollectionMode(context.Background(), args, &output, &diagnostics, func(string) *fetch.Client { called = true; return nil }, true)
			if code != 64 || called || output.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE") {
				t.Fatal("invalid continuation reached client or leaked selectors")
			}
		})
	}
	var output, diagnostics bytes.Buffer
	if runExperimentalCollection(context.Background(), valid, &output, &diagnostics, nil) != 64 || output.Len() != 0 {
		t.Fatal("legacy command acquired context continuation behavior")
	}
}
