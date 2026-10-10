package conformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

func TestCompiledCollectorSyntaxPrivacy(t *testing.T) {
	binaries := buildQueryCLIs(t, "fetch-bundle", "derive-producer-schedule")
	dir := t.TempDir()
	paths := make(map[string]string)
	prior := make(map[string][]byte)
	for _, name := range []string{"bundle", "checkpoint", "schedule"} {
		paths[name] = filepath.Join(dir, "PRIVATE_"+name+".json")
		prior[name] = []byte("PRIVATE_EXISTING_" + name + "\n")
		if err := os.WriteFile(paths[name], prior[name], 0600); err != nil {
			t.Fatal(err)
		}
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected fixture request", http.StatusInternalServerError)
	}))
	defer server.Close()
	peer := server.URL + "/PRIVATE_RPC_PATH?token=PRIVATE_RPC_TOKEN"
	unchanged := func() {
		t.Helper()
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != len(paths) || requests.Load() != 0 {
			t.Fatal("invalid syntax or help reached output publication or loopback RPC")
		}
		for name, path := range paths {
			raw, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, prior[name]) {
				t.Fatal("invalid syntax or help changed an existing output")
			}
		}
	}
	type variant struct {
		name string
		args []string
	}
	shared := []variant{
		{"unknown_name", []string{"--PRIVATE_SYNTAX_TOKEN"}},
		{"unknown_equals", []string{"--PRIVATE_SYNTAX_TOKEN=https://PRIVATE_USER:PRIVATE_SECRET@invalid.example/PRIVATE_PATH"}},
		{"three_dashes", []string{"---PRIVATE_SYNTAX_TOKEN"}},
		{"empty_name", []string{"--=PRIVATE_SYNTAX_TOKEN"}},
		{"missing_peers", []string{"--peers"}},
		{"missing_out", []string{"--out"}},
	}
	type control struct {
		Command  string `json:"command"`
		Variant  string `json:"variant"`
		ExitCode int    `json:"exit_code"`
	}
	var records []control
	for _, command := range []string{"fetch-bundle", "derive-producer-schedule"} {
		variants := slices.Clone(shared)
		base := []string{"--peers", peer + "," + peer + "&alias=2"}
		positional := "positional arguments are not supported"
		if command == "fetch-bundle" {
			base = append(base, "--rpc", peer, "--out", paths["bundle"], "--checkpoint", paths["checkpoint"])
			positional = "fetch-bundle does not accept positional arguments"
			variants = append(variants,
				variant{"invalid_height", []string{"--height", "PRIVATE_SYNTAX_TOKEN"}},
				variant{"invalid_count", []string{"--count", "PRIVATE_SYNTAX_TOKEN"}},
				variant{"invalid_quorum", []string{"--quorum", "PRIVATE_SYNTAX_TOKEN"}},
				variant{"invalid_safety_margin", []string{"--safety-margin", "PRIVATE_SYNTAX_TOKEN"}},
				variant{"invalid_timeout", []string{"--timeout", "PRIVATE_SYNTAX_TOKEN"}},
				variant{"invalid_proof_only", []string{"--proof-only=PRIVATE_SYNTAX_TOKEN"}},
				variant{"overflow_height", []string{"--height", "18446744073709551616"}},
				variant{"overflow_count", []string{"--count", "18446744073709551616"}},
				variant{"overflow_safety_margin", []string{"--safety-margin", "18446744073709551616"}},
				variant{"missing_height", []string{"--height"}},
				variant{"missing_count", []string{"--count"}},
				variant{"missing_timeout", []string{"--timeout"}},
			)
		} else {
			base = append(base, "--from", "2", "--through", "3", "--out", paths["schedule"])
			for _, flag := range []string{"from", "through", "chain-id", "batch-size", "quorum", "timeout"} {
				variants = append(variants, variant{"invalid_" + flag, []string{"--" + flag, "PRIVATE_SYNTAX_TOKEN"}})
				variants = append(variants, variant{"missing_" + flag, []string{"--" + flag}})
			}
			for _, flag := range []string{"from", "through", "chain-id", "batch-size"} {
				variants = append(variants, variant{"overflow_" + flag, []string{"--" + flag, "18446744073709551616"}})
			}
		}
		invoke := func(args ...string) queryCLIResult {
			t.Helper()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binaries[command], args...)
			cmd.Env = append(queryCLIEnvironment(),
				"ZENON_SPV_RPC=https://PRIVATE_ENV_USER:PRIVATE_ENV_PASSWORD@invalid.example/PRIVATE_ENV_PATH",
				"ZENON_SPV_PEERS=https://PRIVATE_ENV_PEER_A.invalid,https://PRIVATE_ENV_PEER_B.invalid")
			cmd.WaitDelay = time.Second
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			var exit *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatal("syntax or help changed the existing tool exit contract")
			}
			r := queryCLIResult{code: exit.ExitCode(), stdout: stdout.Bytes(), stderr: stderr.Bytes()}
			assertOperatorPrivacy(t, r, dir)
			unchanged()
			return r
		}
		for _, variant := range variants {
			r := invoke(append(slices.Clone(base), variant.args...)...)
			if len(r.stdout) != 0 || string(r.stderr) != command+": invalid command syntax\n" {
				t.Fatalf("%s/%s lost its private syntax refusal contract", command, variant.name)
			}
			records = append(records, control{command, variant.name, r.code})
		}
		r := invoke(append(slices.Clone(base), "PRIVATE_POSITIONAL_TOKEN")...)
		if len(r.stdout) != 0 || string(r.stderr) != command+": "+positional+"\n" {
			t.Fatal("positional refusal echoed its value or changed its existing diagnostic")
		}
		records = append(records, control{command, "positional", r.code})
		var help []byte
		for _, option := range []string{"--help", "-h"} {
			r := invoke(append(slices.Clone(base), option)...)
			if len(r.stdout) != 0 || !strings.HasPrefix(string(r.stderr), "Usage of "+command+":\n") ||
				!strings.Contains(string(r.stderr), "-peers") || !strings.Contains(string(r.stderr), "-out") ||
				!strings.HasSuffix(string(r.stderr), command+": flag: help requested\n") {
				t.Fatal("explicit help changed its existing usage or stream contract")
			}
			if help != nil && !bytes.Equal(help, r.stderr) {
				t.Fatal("short and long help differ or disclose selected private values")
			}
			help = slices.Clone(r.stderr)
		}
	}
	if len(records) != 42 {
		t.Fatal("incomplete selected collector syntax refusal inventory")
	}
	raw, err := json.Marshal(struct {
		Version            int       `json:"schema_version"`
		Controls           []control `json:"controls"`
		SyntaxRefusals     int       `json:"syntax_refusals"`
		PositionalRefusals int       `json:"positional_refusals"`
		HelpControls       int       `json:"help_controls"`
		RPCRequests        int64     `json:"rpc_requests"`
		OutputWrites       int       `json:"output_writes"`
	}{1, records, 40, 2, 4, requests.Load(), 0})
	if err != nil {
		t.Fatal("cannot encode collector syntax control inventory")
	}
	t.Logf("offline-collector-syntax-controls %s", raw)
}
