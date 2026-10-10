package conformance_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// Independently selected invalid argument pairs must fail before any missing
// file, writer lock or loopback RPC is reached. These are invocation controls,
// not authenticated network observations or new cryptographic proof vectors.
func TestCompiledVerifierSelectionGuards(t *testing.T) {
	binary := buildQueryCLIs(t, "zenon-spv")["zenon-spv"]
	dir := t.TempDir()
	missing := filepath.Join(dir, "PRIVATE_MISSING.json")
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected fixture request", http.StatusInternalServerError)
	}))
	defer server.Close()
	type control struct {
		Command  string `json:"command"`
		Selector string `json:"selector"`
		Variant  string `json:"variant"`
		ExitCode int    `json:"exit_code"`
	}
	var records []control
	check := func(command, name, variant string, pair []string) {
		t.Helper()
		args := []string{command, "--json"}
		// A selector appearing in this base is removed before adding the
		// deliberate pair. All other missing files stay independently fixed.
		base := []struct{ name, value string }{
			{"genesis-config", missing}, {"protocol-profile", missing},
			{"schedule", missing}, {"window", "low"}, {"retain-headers", "256"},
		}
		if command != "inspect-config" {
			base = append(base, struct{ name, value string }{"state", missing})
		}
		if command == "watch" {
			base = append(base, struct{ name, value string }{"rpc", server.URL})
		}
		for _, selected := range base {
			if selected.name != name {
				args = append(args, "--"+selected.name, selected.value)
			}
		}
		args = append(args, pair...)
		if strings.HasPrefix(command, "verify-") {
			args = append(args, missing)
		}
		r := runQueryCLI(t, binary, args...)
		assertOperatorPrivacy(t, r, dir)
		if r.code != 64 {
			t.Fatalf("%s/%s/%s did not refuse before setup: exit=%d", command, name, variant, r.code)
		}
		if command == "watch" {
			if len(r.stdout) != 0 || string(r.stderr) != "--"+name+" must occur at most once\n" {
				t.Fatal("watch did not privately refuse a repeated selector")
			}
		} else {
			var report struct {
				Command string `json:"command"`
				Code    int    `json:"exit_code"`
				Error   *struct {
					Stage    string `json:"stage"`
					Category string `json:"category"`
				} `json:"error"`
				Context json.RawMessage   `json:"verification_context"`
				Tip     json.RawMessage   `json:"verification_tip"`
				Outcome json.RawMessage   `json:"outcome"`
				Results []json.RawMessage `json:"results"`
			}
			if len(r.stderr) != 0 || json.Unmarshal(r.stdout, &report) != nil || report.Command != command || report.Code != 64 ||
				report.Error == nil || report.Error.Stage != "arguments" || report.Error.Category != "usage" ||
				(len(report.Context) != 0 && string(report.Context) != "null") ||
				(len(report.Tip) != 0 && string(report.Tip) != "null") ||
				(len(report.Outcome) != 0 && string(report.Outcome) != "null") || len(report.Results) != 0 {
				t.Fatal("repeated selector lost JSON framing or reached verification setup")
			}
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 || requests.Load() != 0 {
			t.Fatal("repeated selector loaded a writer path or contacted RPC")
		}
		records = append(records, control{command, name, variant, r.code})
	}
	variants := func(name, value string, commands []string) {
		for _, tc := range []struct {
			name string
			pair []string
		}{
			{"identical", []string{"--" + name + "=" + value, "--" + name + "=" + value}},
			{"mixed_dash", []string{"-" + name + "=" + value, "--" + name + "=PRIVATE_OTHER"}},
			{"empty_then_value", []string{"--" + name + "=", "--" + name + "=" + value}},
			{"private_then_value", []string{"--" + name + "=PRIVATE_FIRST", "--" + name + "=" + value}},
			{"value_then_private", []string{"--" + name + "=" + value, "-" + name + "=PRIVATE_LAST"}},
		} {
			for _, command := range commands {
				check(command, name, tc.name, tc.pair)
			}
		}
	}
	verify := []string{"verify-headers", "verify-commitment", "verify-segment", "verify-state-value"}
	for _, tc := range []struct{ name, value string }{
		{"genesis-config", missing}, {"protocol-profile", missing}, {"schedule", missing},
		{"window", "low"}, {"retain-headers", "256"}, {"state", missing},
	} {
		commands := append(slices.Clone(verify), "inspect-state", "watch")
		if tc.name != "state" {
			commands = append(commands, "inspect-config")
		}
		variants(tc.name, tc.value, commands)
	}
	variants("retained-only", "true", verify)
	for _, command := range verify {
		check(command, "retained-only", "bare_then_false", []string{"--retained-only", "-retained-only=false"})
	}
	for _, tc := range []struct{ name, value string }{
		{"rpc", server.URL}, {"peers", server.URL}, {"quorum", "1"}, {"once", "true"},
		{"interval", "1s"}, {"safety-margin", "1"}, {"batch-size", "1"},
	} {
		variants(tc.name, tc.value, []string{"watch"})
	}
	check("watch", "once", "bare_then_false", []string{"--once", "-once=false"})
	if len(records) != 265 {
		t.Fatal("incomplete selected refusal inventory")
	}
	// Omission and one explicit setting retain their existing configuration
	// behavior. Presentation flags deliberately retain ordinary flag semantics.
	for _, args := range [][]string{
		{"inspect-config", "--json"},
		{"inspect-config", "--json", "--json", "--window=low", "--retain-headers=256"},
	} {
		r := runQueryCLI(t, binary, args...)
		assertOperatorPrivacy(t, r, dir)
		var report struct {
			Status  string          `json:"status"`
			Code    int             `json:"exit_code"`
			Context json.RawMessage `json:"verification_context"`
		}
		if r.code != 0 || len(r.stderr) != 0 || json.Unmarshal(r.stdout, &report) != nil ||
			report.Code != 0 || report.Status != "configured" || len(report.Context) == 0 || string(report.Context) == "null" {
			t.Fatal("ordinary configuration selection changed")
		}
	}
	raw, err := json.Marshal(struct {
		Version       int       `json:"schema_version"`
		Controls      []control `json:"controls"`
		Configuration int       `json:"configuration_controls"`
		RPCRequests   int64     `json:"rpc_requests"`
	}{1, records, 2, requests.Load()})
	if err != nil {
		t.Fatal("cannot encode selection control inventory")
	}
	t.Logf("offline-verifier-selection-controls %s", raw)
}
