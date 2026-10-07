package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("ZENON_OBSERVER_COLLECTION_TEST") == "1" {
		if len(os.Args) > 1 && os.Args[1] == "--rpc" {
			_, _ = os.Stderr.WriteString("PRIVATE_COLLECTOR_DIAGNOSTIC\n")
			if os.Getenv("ZENON_OBSERVER_COLLECTION_LARGE") == "1" {
				// Stream a bounded, syntax-valid fixture without retaining it in
				// the child. The parent captures it just like ordinary collection.
				_, _ = os.Stdout.WriteString(`{"data":"`)
				chunk := bytes.Repeat([]byte{'x'}, 1<<20)
				for range 32 {
					if _, err := os.Stdout.Write(chunk); err != nil {
						os.Exit(71)
					}
				}
				_, _ = os.Stdout.WriteString(`"}`)
				os.Exit(0)
			}
			_, _ = os.Stdout.WriteString(os.Getenv("ZENON_OBSERVER_COLLECTION_OUTPUT"))
			os.Exit(0)
		}
		// Positive control: a syntax-valid but semantically empty object reaches
		// the verifier. Non-JSON collection must never reach this branch.
		_ = os.WriteFile(os.Getenv("ZENON_OBSERVER_COLLECTION_CANARY"), []byte("started"), 0o600)
		os.Exit(70)
	}
	os.Exit(m.Run())
}

func selectedCollectionArguments() []string {
	args := selectedArguments()
	i := slices.Index(args, "--bundle")
	args = append(args[:i:i], args[i+2:]...)
	return append(args, "--collector", "PRIVATE_COLLECTOR", "--collector-sha256", strings.Repeat("b", 64),
		"--rpc", "http://PRIVATE_USER:PRIVATE_PASSWORD@localhost/PRIVATE_PATH?key=PRIVATE_TOKEN",
		"--height", "100", "--count", "16", "--segments", "PRIVATE_ADDRESS:1-5")
}

func TestCollectionRequiresCompleteExplicitSelection(t *testing.T) {
	args := selectedCollectionArguments()
	if _, ok := parseConfiguration(args); !ok {
		t.Fatal("complete single-RPC selection refused")
	}
	for i := 0; i < len(args); i += 2 {
		without := append(slices.Clone(args[:i]), args[i+2:]...)
		without = append(without, "--timeout", "1s")
		if _, ok := parseConfiguration(without); ok {
			t.Fatal("incomplete RPC selection accepted")
		}
		if _, ok := parseConfiguration(append(slices.Clone(args), args[i:i+2]...)); ok {
			t.Fatal("duplicate RPC selection accepted")
		}
	}
	for _, extra := range [][]string{{"--bundle", "PRIVATE_BUNDLE"}, {"--commitments", "PRIVATE_ADDRESS"}, {"--peers", "PRIVATE_RPC"}} {
		if _, ok := parseConfiguration(append(slices.Clone(args), extra...)); ok {
			t.Fatal("ambiguous proof source or target mode accepted")
		}
	}
	for _, name := range []string{"collector", "collector-sha256", "rpc", "height", "count", "commitments", "segments", "momentum-heights"} {
		if _, ok := parseConfiguration(append(selectedArguments(), "--"+name, "PRIVATE_UNUSED")); ok {
			t.Fatal("local-file observation accepted unused RPC inputs")
		}
	}
	for _, tc := range []struct{ option, value string }{
		{"--height", "-1"}, {"--height", "0"}, {"--height", "16"}, {"--height", "9223372036854775808"},
		{"--count", "0"}, {"--count", "17"}, {"--count", "PRIVATE"}, {"--count", "1.0"},
		{"--collector-sha256", strings.Repeat("B", 64)}, {"--rpc", "PRIVATE_RPC"}, {"--rpc", "ws://localhost/PRIVATE"},
		{"--rpc", "http://localhost/PRIVATE#fragment"}, {"--rpc", "http://:80/PRIVATE"}, {"--rpc", "http://localhost/" + strings.Repeat("x", 4096)},
		{"--segments", " "}, {"--segments", strings.Repeat("x", (32<<10)+1)},
	} {
		changed := slices.Clone(args)
		changed[slices.Index(changed, tc.option)+1] = tc.value
		var out, diagnostics bytes.Buffer
		if run(context.Background(), changed, &out, &diagnostics) != 64 || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE") {
			t.Fatal("invalid collection selection executed or leaked private input")
		}
	}
	commitments := slices.Clone(args)
	commitments[slices.Index(commitments, "--command")+1] = "verify-commitment"
	commitments[slices.Index(commitments, "--segments")] = "--commitments"
	if _, ok := parseConfiguration(commitments); !ok {
		t.Fatal("complete commitment selection refused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, diagnostics bytes.Buffer
	if run(ctx, args, &out, &diagnostics) != 2 || diagnostics.Len() != 0 || bytes.Contains(out.Bytes(), []byte("PRIVATE")) || !bytes.Contains(out.Bytes(), []byte(`"schema_version":2`)) {
		t.Fatal("cancelled collection executed, changed schema or leaked")
	}
}

func TestCollectionExplicitMomentumSelection(t *testing.T) {
	args := selectedCollectionArguments()
	selected := append(slices.Clone(args), "--momentum-heights", "85,90,100")
	c, ok := parseConfiguration(selected)
	if !ok || !slices.Equal(collectionArguments(c), []string{"--rpc", c.collection.rpc, "--height", "100", "--count", "16",
		"--proof-only", "--out", "-", "--timeout", "30s", "--momentum-heights", "85,90,100", "--segments", c.collection.segments}) {
		t.Fatal("explicit height selection changed collection arguments")
	}
	if _, ok := parseConfiguration(append(selected, "--momentum-heights", "90")); ok {
		t.Fatal("duplicate selection accepted")
	}
	for _, value := range []string{"", "84", "101", "85,85", "90,85", " 90", "090", strings.Repeat("1,", 1024) + "90"} {
		var out, diagnostics bytes.Buffer
		if run(context.Background(), append(slices.Clone(args), "--momentum-heights", value), &out, &diagnostics) != 64 || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE") {
			t.Fatal("invalid selected evidence executed or disclosed private inputs")
		}
	}
}

func TestCollectionRefusesZeroExitWithoutCompleteJSON(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("cannot select process fixture")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("cannot pin process fixture")
	}
	h := sha256.Sum256(raw)
	dir := t.TempDir()
	canary := filepath.Join(dir, "PRIVATE_CANARY")
	t.Setenv("ZENON_OBSERVER_COLLECTION_TEST", "1")
	t.Setenv("ZENON_OBSERVER_COLLECTION_CANARY", canary)
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	for _, tc := range []struct {
		name, output, category string
		verifierStarted        bool
	}{
		{"empty", "", "invalid_bundle", false}, {"truncated", "{", "invalid_bundle", false},
		{"extra document", "{}\n{}\n", "invalid_bundle", false}, {"private raw text", "PRIVATE_RAW_OUTPUT", "invalid_bundle", false},
		{"valid syntax still needs verification", "{}\n", "process_failure", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ZENON_OBSERVER_COLLECTION_OUTPUT", tc.output)
			args := selectedCollectionArguments()
			for _, name := range []string{"collector", "verifier", "consumer"} {
				args[slices.Index(args, "--"+name)+1] = binary
				args[slices.Index(args, "--"+name+"-sha256")+1] = hex.EncodeToString(h[:])
			}
			for _, name := range []string{"genesis-config", "protocol-profile", "schedule", "state", "expectations"} {
				path := filepath.Join(dir, "PRIVATE_"+name)
				if os.WriteFile(path, []byte("PRIVATE_INPUT"), 0o600) != nil {
					t.Fatal("cannot stage local fixture")
				}
				args[slices.Index(args, "--"+name)+1] = path
			}
			args[slices.Index(args, "--private-dir")+1] = dir
			args = append(args, "--timeout", "5s")
			var out, diagnostics bytes.Buffer
			if run(context.Background(), args, &out, &diagnostics) != 2 || diagnostics.Len() != 0 || bytes.Contains(out.Bytes(), []byte("PRIVATE")) {
				t.Fatal("bad collection acquired success or disclosed raw bytes")
			}
			var result summary
			if json.Unmarshal(out.Bytes(), &result) != nil || result.Version != 2 || result.Status != "not_matched" ||
				result.Category == nil || *result.Category != tc.category || result.CheckedTargets != 0 ||
				result.Collector == nil || result.Collector.ExitCode == nil || *result.Collector.ExitCode != 0 ||
				(result.Verifier.ExitCode != nil) != tc.verifierStarted || result.Consumer.ExitCode != nil {
				t.Fatal("zero-exit collection lost its actual status or stage boundary")
			}
			_, err := os.Stat(canary)
			if (err == nil) != tc.verifierStarted || (err != nil && !os.IsNotExist(err)) {
				t.Fatal("incomplete collection started the verifier")
			}
			files, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal("cannot inspect cleanup")
			}
			for _, file := range files {
				if strings.HasPrefix(file.Name(), "block-observation-") {
					t.Fatal("failed collection leaked its private run directory")
				}
			}
		})
	}
}
