package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestCLIInvalidWindowCannotAdvanceState(t *testing.T) {
	bundlePath, anchorPath := stateValueBundleFromLongChain(t, 6, nil)
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
		for _, tier := range []string{"hgih", "HIGH", "", " high", "low ", "private-tier-value"} {
			for _, existing := range []bool{false, true} {
				stateMode := "new"
				if existing {
					stateMode = "existing"
				}
				t.Run(name+"/"+tier+"/"+stateMode, func(t *testing.T) {
					statePath := filepath.Join(t.TempDir(), "state.json")
					before := []byte("existing state must remain untouched")
					if existing {
						if err := os.WriteFile(statePath, before, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					args := []string{"--window", tier, "--state", statePath, "--show-context", "--genesis-config", anchorPath}
					if name == "watch" {
						args = append(args, "--peers", server.URL)
					} else {
						args = append(args, bundlePath)
					}
					code, out, diagnostics := captureSetupRun(t, func() int { return run(args) })
					if code != 64 || out != "" || !strings.Contains(diagnostics, "--window must be low, medium, or high") {
						t.Fatalf("invalid window reached verification: code=%d out=%s diagnostics=%s", code, out, diagnostics)
					}
					for _, unexpected := range []string{"verification_context:", "watching:", "private-tier-value"} {
						if strings.Contains(diagnostics, unexpected) {
							t.Fatalf("invalid window reported %q", unexpected)
						}
					}
					if after, err := os.ReadFile(statePath); existing {
						if err != nil || !bytes.Equal(before, after) {
							t.Fatalf("existing state changed: %v", err)
						}
					} else if !os.IsNotExist(err) {
						t.Fatalf("invalid window created state: %v", err)
					}
					if requests.Load() != 0 {
						t.Fatal("invalid window triggered RPC activity")
					}
				})
			}
		}
	}
}

func TestCLIWindowCapturesDocumentedDepth(t *testing.T) {
	bundlePath, anchorPath := stateValueBundleFromLongChain(t, 6, nil)
	for _, tc := range []struct {
		name  string
		args  []string
		depth uint64
	}{
		{"default", nil, 6}, {"low", []string{"--window", "low"}, 6},
		{"medium", []string{"--window", "medium"}, 60}, {"high", []string{"--window", "high"}, 360},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--genesis-config", anchorPath, "--show-context"}, tc.args...)
			args = append(args, bundlePath)
			var context verifierContext
			code, out, diagnostics := captureSetupRun(t, func() int {
				var code int
				context, code = prepareVerifierContext("verify-headers", args, newVerificationOutput("verify-headers", os.Stdout, os.Stderr))
				return code
			})
			if code != 0 || diagnostics != "" {
				t.Fatalf("valid tier failed setup: code=%d diagnostics=%s", code, diagnostics)
			}
			want := verify.DefaultPolicy()
			want.W = tc.depth
			if context.opts.Policy != want || readCLIContext(t, out).Policy.W != tc.depth {
				t.Fatalf("tier %s changed depth or resource limits", tc.name)
			}
		})
	}
}

func TestWatchRejectsPositionalArgumentsBeforeConfiguration(t *testing.T) {
	for _, extra := range [][]string{{"private-extra-argument"}, {"private-extra-argument", "--window", "high"}} {
		args := []string{"--state", filepath.Join(t.TempDir(), "state.json"), "--rpc", "http://127.0.0.1:1",
			"--genesis-config", filepath.Join(t.TempDir(), "absent-anchor.json")}
		code, out, diagnostics := captureSetupRun(t, func() int { return runWatch(append(args, extra...)) })
		if code != 64 || out != "" || !strings.Contains(diagnostics, "watch does not accept positional arguments") {
			t.Fatalf("watch ignored extra arguments: code=%d out=%s diagnostics=%s", code, out, diagnostics)
		}
		if strings.Contains(diagnostics, "private-extra-argument") || strings.Contains(diagnostics, "genesis:") {
			t.Fatal("watch echoed untrusted arguments or read configuration")
		}
	}
}
