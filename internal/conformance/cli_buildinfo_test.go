package conformance_test

import (
	"bytes"
	"context"
	binaryinfo "debug/buildinfo"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompiledCLIBuildIdentity(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	for name, bin := range buildQueryCLIs(t) {
		embedded, err := binaryinfo.ReadFile(bin)
		if err != nil {
			t.Fatal(err)
		}
		settings := make(map[string]string)
		for _, setting := range embedded.Settings {
			settings[setting.Key] = setting.Value
		}
		for _, entry := range []string{"version", "--version"} {
			t.Run(name+"/"+entry, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, bin, entry, "--json")
				cmd.Env = append(queryCLIEnvironment(),
					"ZENON_SPV_RPC="+server.URL+"/PRIVATE_RPC",
					"ZENON_SPV_PEERS="+server.URL+"/PRIVATE_PEERS",
					"ZENON_SPV_GENESIS_HASH=PRIVATE_INVALID_ANCHOR",
					"ZENON_SPV_CHAIN_ID=PRIVATE_INVALID_CHAIN")
				var out, diagnostics bytes.Buffer
				cmd.Stdout, cmd.Stderr, cmd.WaitDelay = &out, &diagnostics, time.Second
				if err := cmd.Run(); err != nil || diagnostics.Len() != 0 || requests.Load() != 0 || bytes.Contains(out.Bytes(), []byte("PRIVATE")) {
					t.Fatalf("version command accessed RPC/configuration or failed: %v", err)
				}
				var report struct {
					SchemaVersion uint32 `json:"schema_version"`
					Command       string `json:"command"`
					GoVersion     string `json:"go_version"`
					OS            string `json:"os"`
					Architecture  string `json:"architecture"`
					Source        *struct {
						VCS      string `json:"vcs"`
						Revision string `json:"revision"`
						Modified bool   `json:"modified"`
					} `json:"source"`
				}
				decoder := json.NewDecoder(&out)
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&report); err != nil {
					t.Fatal(err)
				}
				if err := decoder.Decode(new(any)); err != io.EOF || report.SchemaVersion != 1 || report.Command != name || report.OS != runtime.GOOS || report.Architecture != runtime.GOARCH || report.GoVersion == "" {
					t.Fatal("build report identity or JSON framing mismatch")
				}
				if settings["vcs"] == "git" {
					if report.Source == nil || report.Source.VCS != "git" || report.Source.Revision != settings["vcs.revision"] || report.Source.Modified != (settings["vcs.modified"] == "true") {
						t.Fatal("reported source differs from the actual executable metadata")
					}
				} else if report.Source != nil {
					t.Fatal("binary without Git stamping claimed a known source")
				}
			})
		}
	}
}
