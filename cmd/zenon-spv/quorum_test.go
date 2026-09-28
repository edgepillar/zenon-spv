package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestWatchQuorumValidationPrecedesConfiguration(t *testing.T) {
	var requests atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	a, b := httptest.NewServer(handler), httptest.NewServer(handler)
	defer a.Close()
	defer b.Close()
	for _, peers := range [][]string{{a.URL}, {a.URL, b.URL}} {
		for _, q := range []int{-1, 0, 1, 2, 3} {
			t.Run(fmt.Sprintf("peers-%d/quorum-%d", len(peers), q), func(t *testing.T) {
				dir := t.TempDir()
				code, out, diagnostics := captureSetupRun(t, func() int {
					return runWatch([]string{"--peers", strings.Join(peers, ","), "--quorum", fmt.Sprint(q),
						"--state", filepath.Join(dir, "state.json"), "--genesis-config", filepath.Join(dir, "absent-anchor.json"), "--show-context"})
				})
				if q < 0 || q > len(peers) {
					if code != 64 || !strings.Contains(diagnostics, "--quorum must be 0 (unanimous) or between 1 and the number of peers") {
						t.Fatalf("invalid quorum reached configuration: code=%d diagnostics=%s", code, diagnostics)
					}
				} else if code != 70 || !strings.HasPrefix(diagnostics, "genesis: ") {
					t.Fatalf("valid quorum did not reach configuration: code=%d diagnostics=%s", code, diagnostics)
				}
				if out != "" || strings.Contains(diagnostics, "verification_context:") || requests.Load() != 0 {
					t.Fatal("failed setup reached evidence reporting or RPC activity")
				}
			})
		}
	}
}
