package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestAmbiguousProfileStopsAllCommandsBeforeEvidenceOrState(t *testing.T) {
	profile := verify.ProtocolProfile{Version: 1,
		Anchor:       verify.GenesisTrustRoot{ChainID: 0, Height: 100, HeaderHash: chain.Hash{1}},
		ValidThrough: 200, V2FromHeight: 150, Source: "synthetic CLI profile"}
	setAnchorEnvironment(t, profile.Anchor)
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	for name, run := range map[string]func([]string) int{
		"headers": runVerifyHeaders, "commitment": runVerifyCommitment,
		"segment": runVerifySegment, "state-value": runVerifyStateValue, "watch": runWatch,
	} {
		for kind, input := range map[string]string{
			"duplicate activation":  `{"v2_from_height":0,` + string(raw[1:]),
			"omitted zero chain ID": strings.Replace(string(raw), `"chain_id":0,`, "", 1),
		} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				dir := t.TempDir()
				profilePath, statePath := filepath.Join(dir, "profile.json"), filepath.Join(dir, "state.json")
				before := []byte("existing state must remain untouched")
				if err := os.WriteFile(profilePath, []byte(input), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(statePath, before, 0o600); err != nil {
					t.Fatal(err)
				}
				args := []string{"--state", statePath, "--show-context", "--protocol-profile", profilePath}
				if name == "watch" {
					args = append(args, "--peers", server.URL)
				} else {
					args = append(args, filepath.Join(dir, "absent-bundle.json"))
				}
				code, out, diagnostics := captureSetupRun(t, func() int { return run(args) })
				if code != 70 || out != "" || !strings.HasPrefix(diagnostics, "protocol profile: ") || strings.Contains(diagnostics, "verification_context:") {
					t.Fatalf("ambiguous profile reached verification: code=%d out=%s diagnostics=%s", code, out, diagnostics)
				}
				if after, err := os.ReadFile(statePath); err != nil || !bytes.Equal(before, after) {
					t.Fatalf("existing state changed: %v", err)
				}
				if requests.Load() != 0 {
					t.Fatal("ambiguous profile triggered RPC activity")
				}
			})
		}
	}
}
