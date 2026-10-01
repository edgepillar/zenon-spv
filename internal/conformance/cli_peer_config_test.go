package conformance_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCompiledCLIDuplicatePeerConfiguration(t *testing.T) {
	bins := buildQueryCLIs(t)
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	endpoint := strings.Replace(server.URL, "http://", "http://PRIVATE_RPC_USER:PRIVATE_RPC_PASSWORD@", 1) + "?token=PRIVATE_RPC_QUERY"
	dir := t.TempDir()
	state, bundle, checkpoint := filepath.Join(dir, "PRIVATE_STATE.json"), filepath.Join(dir, "PRIVATE_BUNDLE.json"), filepath.Join(dir, "PRIVATE_CHECKPOINT.json")
	for _, path := range []string{state, bundle, checkpoint} {
		if err := os.WriteFile(path, []byte("PRIVATE_EXISTING_FILE"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(protectCLIState(t, path))
	}
	for _, quorum := range []string{"0", "2"} {
		for _, command := range []string{"watch", "fetch-bundle"} {
			t.Run(fmt.Sprintf("%s/quorum-%s", command, quorum), func(t *testing.T) {
				binary, wantCode := bins["fetch-bundle"], 1
				args := []string{"--peers", endpoint + "," + endpoint, "--quorum", quorum}
				if command == "watch" {
					binary, wantCode = bins["zenon-spv"], 64
					args = append([]string{"watch"}, args...)
					args = append(args, "--state", state, "--genesis-config", filepath.Join(dir, "PRIVATE_ABSENT_ANCHOR"), "--show-context")
				} else {
					args = append(args, "--height", "99", "--count", "1", "--out", bundle, "--checkpoint", checkpoint)
				}
				result := runQueryCLI(t, binary, args...)
				if result.code != wantCode || len(result.stdout) != 0 || !bytes.Contains(result.stderr, []byte("peer[2] duplicates the configured URL of peer[1]")) || bytes.Contains(result.stderr, []byte("PRIVATE")) {
					t.Fatalf("duplicate peers did not produce a private configuration failure: exit=%d", result.code)
				}
				if requests.Load() != 0 {
					t.Fatal("duplicate configuration issued RPC requests")
				}
				if _, err := os.Stat(state + ".lock"); !os.IsNotExist(err) {
					t.Fatal("duplicate configuration acquired a state writer companion")
				}
			})
		}
	}
}
