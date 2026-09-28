package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestVerifyHeadersCLI_ProtocolProfile(t *testing.T) {
	raw, err := os.ReadFile("../../internal/testdata/conformance/momentum-v1-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Transition struct {
			Anchor       verify.GenesisTrustRoot `json:"anchor"`
			V2FromHeight uint64                  `json:"v2_from_height"`
			Vectors      []struct {
				Header chain.Header `json:"header"`
			} `json:"vectors"`
		} `json:"transition"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	headers := make([]chain.Header, len(corpus.Transition.Vectors))
	for i, v := range corpus.Transition.Vectors {
		headers[i] = v.Header
	}
	if len(headers) != 6 {
		t.Fatal("incomplete transition corpus")
	}
	anchor := corpus.Transition.Anchor
	profile := verify.ProtocolProfile{Version: 1, Anchor: anchor, ValidThrough: 2006,
		V2FromHeight: corpus.Transition.V2FromHeight, Source: "synthetic CLI test"}
	write := func(path string, v any) {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	genesisPath, profilePath, bundlePath := filepath.Join(dir, "anchor.json"), filepath.Join(dir, "profile.json"), filepath.Join(dir, "bundle.json")
	write(genesisPath, anchor)
	write(profilePath, profile)
	write(bundlePath, proof.HeaderBundle{Version: proof.WireVersion, ChainID: anchor.ChainID,
		ClaimedGenesis: anchor.HeaderHash, Headers: headers})
	statePath := filepath.Join(dir, "state.json")
	args := []string{"--genesis-config", genesisPath, "--state", statePath}
	code, out := captureRun(t, func() int { return runVerifyHeaders(append(args, bundlePath)) })
	if code != 2 || !strings.Contains(out, "ReasonProtocolProfileRequired") || strings.Contains(out, "ACCEPT") {
		t.Fatalf("missing profile: code=%d out=%s", code, out)
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing profile persisted progress")
	}
	withProfile := append(slices.Clone(args), "--protocol-profile", profilePath, bundlePath)
	code, out = captureRun(t, func() int { return runVerifyHeaders(withProfile) })
	if code != 0 || !strings.Contains(out, "ACCEPT") || !strings.Contains(out, "TRUST_EXTERNAL_PROTOCOL_PROFILE") {
		t.Fatalf("profile acceptance: code=%d out=%s", code, out)
	}
	state, err := verify.LoadHeaderState(statePath)
	if err != nil || state.ProtocolProfile == nil || state.RetainedWindow[5].NextWorkPrice != headers[5].NextWorkPrice {
		t.Fatalf("profile/price persistence failed: %v", err)
	}
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	code, _ = captureRun(t, func() int { return runVerifyHeaders(append(args, bundlePath)) })
	if code != 70 {
		t.Fatalf("profile downgrade on resume: code=%d", code)
	}
	after, err := os.ReadFile(statePath)
	if err != nil || string(before) != string(after) {
		t.Fatal("failed resume changed state")
	}
}
