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

// Exercise the ordinary executable, including dispatch before a subcommand's
// parser. Selected private argument sentinels must never appear in diagnostics.
// These are offline invocation controls, not authenticated network observations.
func TestCompiledVerifierSyntaxPrivacy(t *testing.T) {
	binary := buildQueryCLIs(t, "zenon-spv")["zenon-spv"]
	dir := t.TempDir()
	missing := filepath.Join(dir, "PRIVATE_MISSING.json")
	state := filepath.Join(dir, "PRIVATE_STATE.json")
	prior := []byte("PRIVATE_EXISTING_STATE_SENTINEL\n")
	if err := os.WriteFile(state, prior, 0600); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected fixture request", http.StatusInternalServerError)
	}))
	defer server.Close()
	type control struct {
		Command  string `json:"command"`
		Variant  string `json:"variant"`
		JSON     bool   `json:"json_requested"`
		ExitCode int    `json:"exit_code"`
	}
	var records []control
	commands := []string{"verify-headers", "verify-commitment", "verify-segment", "verify-state-value", "watch"}
	variants := []struct {
		name string
		args []string
	}{
		{"unknown_name", []string{"--PRIVATE_SYNTAX_TOKEN"}},
		{"unknown_equals", []string{"--PRIVATE_SYNTAX_TOKEN=https://PRIVATE_USER:PRIVATE_SECRET@invalid.example/PRIVATE_PATH"}},
		{"invalid_json", []string{"--json=PRIVATE_SYNTAX_TOKEN"}},
		{"invalid_show_context", []string{"--show-context=PRIVATE_SYNTAX_TOKEN"}},
		{"three_dashes", []string{"---PRIVATE_SYNTAX_TOKEN"}},
		{"empty_name", []string{"--=PRIVATE_SYNTAX_TOKEN"}},
		{"missing_genesis_value", []string{"--genesis-config"}},
		{"missing_context_pin", []string{"--expect-context"}},
	}
	unchanged := func() {
		t.Helper()
		raw, err := os.ReadFile(state)
		entries, listErr := os.ReadDir(dir)
		if err != nil || string(raw) != string(prior) || listErr != nil || len(entries) != 1 || requests.Load() != 0 {
			t.Fatal("syntax or help reached state, writer ownership or loopback RPC")
		}
	}
	for _, command := range commands {
		base := []string{command, "--state", state, "--protocol-profile", missing, "--schedule", missing}
		if command == "watch" {
			base = append(base, "--once", "--rpc", server.URL)
		}
		var help []byte
		for _, jsonRequested := range []bool{false, true} {
			selected := slices.Clone(base)
			if jsonRequested {
				selected = append(selected, "--json")
			}
			for _, variant := range variants {
				args := slices.Clone(selected)
				if variant.name != "missing_genesis_value" {
					args = append(args, "--genesis-config", missing)
				}
				r := runQueryCLI(t, binary, append(args, variant.args...)...)
				assertOperatorPrivacy(t, r, dir)
				if r.code != 64 || len(r.stdout) != 0 || string(r.stderr) != "arguments: invalid command syntax\n" {
					t.Fatalf("%s/%s/json=%t lost the private syntax failure contract", command, variant.name, jsonRequested)
				}
				unchanged()
				records = append(records, control{command, variant.name, jsonRequested, r.code})
			}
			r := runQueryCLI(t, binary, append(selected, "--genesis-config", missing, "--help")...)
			assertOperatorPrivacy(t, r, dir)
			if r.code != 64 || len(r.stdout) != 0 || !strings.HasPrefix(string(r.stderr), "Usage of "+command+":\n") ||
				!strings.Contains(string(r.stderr), "-genesis-config") || !strings.Contains(string(r.stderr), "-json") {
				t.Fatal("explicit help lost its existing stderr/exit contract")
			}
			if jsonRequested && string(r.stderr) != string(help) {
				t.Fatal("JSON selection changed help text or exposed selected private values")
			}
			help = slices.Clone(r.stderr)
			unchanged()
		}
	}
	for i, command := range []string{"PRIVATE_SYNTAX_TOKEN", "https://PRIVATE_USER:PRIVATE_SECRET@invalid.example/PRIVATE_PATH", "---PRIVATE_SYNTAX_TOKEN"} {
		for _, jsonRequested := range []bool{false, true} {
			args := []string{command}
			if jsonRequested {
				args = append(args, "--json")
			}
			r := runQueryCLI(t, binary, args...)
			assertOperatorPrivacy(t, r, dir)
			if r.code != 64 || len(r.stdout) != 0 || !strings.HasPrefix(string(r.stderr), "unknown subcommand\n\n") ||
				!strings.Contains(string(r.stderr), "verify-headers") {
				t.Fatal("dispatch echoed an unknown subcommand or changed its usage contract")
			}
			unchanged()
			records = append(records, control{"unknown", []string{"name", "url", "grammar"}[i], jsonRequested, r.code})
		}
	}
	if len(records) != 86 {
		t.Fatal("incomplete selected syntax refusal inventory")
	}
	raw, err := json.Marshal(struct {
		Version      int       `json:"schema_version"`
		Controls     []control `json:"controls"`
		HelpControls int       `json:"help_controls"`
		RPCRequests  int64     `json:"rpc_requests"`
		StateWrites  int       `json:"state_writes"`
	}{1, records, 10, requests.Load(), 0})
	if err != nil {
		t.Fatal("cannot encode syntax control inventory")
	}
	t.Logf("offline-verifier-syntax-controls %s", raw)
}
