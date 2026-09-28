package main

import (
	"bytes"
	"fmt"
	"io"
	"math"
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

var anchorEnvNames = []string{"ZENON_SPV_GENESIS_HASH", "ZENON_SPV_CHAIN_ID", "ZENON_SPV_GENESIS_HEIGHT"}

func clearAnchorEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range anchorEnvNames {
		// Setenv registers restoration even when the original variable was unset.
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

func setAnchorEnvironment(t *testing.T, anchor verify.GenesisTrustRoot) {
	t.Helper()
	t.Setenv(anchorEnvNames[0], fmt.Sprintf("%x", anchor.HeaderHash[:]))
	t.Setenv(anchorEnvNames[1], fmt.Sprint(anchor.ChainID))
	t.Setenv(anchorEnvNames[2], fmt.Sprint(anchor.Height))
}

func TestLoadGenesisEnvironmentSelection(t *testing.T) {
	clearAnchorEnvironment(t)
	want, err := verify.MainnetGenesis()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := loadGenesis(""); err != nil || got != want {
		t.Fatalf("unconfigured default: got=%+v err=%v", got, err)
	}
	// Every nonempty proper subset must fail, even height alone. Empty-but-set
	// variables also express an override and must never select the default.
	for mask := 1; mask < 8; mask++ {
		for _, empty := range []bool{false, true} {
			t.Run(fmt.Sprintf("mask-%d-empty-%t", mask, empty), func(t *testing.T) {
				clearAnchorEnvironment(t)
				for i, value := range []string{strings.Repeat("01", 32), "7", "12"} {
					if mask&(1<<i) != 0 {
						if empty {
							value = " \t"
						}
						t.Setenv(anchorEnvNames[i], value)
					}
				}
				got, err := loadGenesis("")
				if mask == 7 && !empty {
					if err != nil || got.ChainID != 7 || got.Height != 12 || got.HeaderHash[0] != 1 {
						t.Fatalf("complete override: got=%+v err=%v", got, err)
					}
				} else if err == nil || got != (verify.GenesisTrustRoot{}) {
					t.Fatalf("incomplete override selected anchor=%+v err=%v", got, err)
				}
			})
		}
	}
}

func TestLoadGenesisEnvironmentStrictValues(t *testing.T) {
	anchor := verify.GenesisTrustRoot{ChainID: 7, Height: 12, HeaderHash: chain.Hash{1}}
	for _, name := range anchorEnvNames {
		values := []string{"", " ", "-1", "+1", "1.0", "1e2", "0x10", "18446744073709551616", "12 private-value", "12private-value", "12\n13"}
		switch name {
		case anchorEnvNames[0]:
			values = []string{"", " ", "01", strings.Repeat("0", 64), strings.Repeat("g", 64), strings.Repeat("01", 32) + "private-value"}
		case anchorEnvNames[2]:
			values = append(values, "0")
		}
		for i, value := range values {
			t.Run(fmt.Sprintf("%s-%d", name, i), func(t *testing.T) {
				setAnchorEnvironment(t, anchor)
				t.Setenv(name, value)
				got, err := loadGenesis("")
				if err == nil || got != (verify.GenesisTrustRoot{}) {
					t.Fatalf("invalid value returned anchor=%+v err=%v", got, err)
				}
				if strings.Contains(err.Error(), "private-value") {
					t.Fatal("untrusted environment value reached the error message")
				}
			})
		}
	}
	for _, id := range []uint64{0, math.MaxUint64} {
		anchor.ChainID, anchor.Height = id, math.MaxUint64
		setAnchorEnvironment(t, anchor)
		t.Setenv(anchorEnvNames[0], " \t0x"+fmt.Sprintf("%x", anchor.HeaderHash[:])+"\n")
		t.Setenv(anchorEnvNames[1], " "+fmt.Sprint(id)+" ")
		t.Setenv(anchorEnvNames[2], "\t"+fmt.Sprint(anchor.Height)+"\n")
		if got, err := loadGenesis(""); err != nil || got != anchor {
			t.Fatalf("valid boundary override: got=%+v err=%v", got, err)
		}
	}
}

func TestLoadGenesisConfigTakesPrecedence(t *testing.T) {
	_, path := stateValueBundleFromLongChain(t, 6, nil)
	want, err := verify.LoadGenesisFromConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range anchorEnvNames {
		t.Setenv(name, "invalid-environment")
	}
	if got, err := loadGenesis(path); err != nil || got != want {
		t.Fatalf("config did not override invalid environment: got=%+v err=%v", got, err)
	}
	setAnchorEnvironment(t, want)
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := loadGenesis(path); err == nil || got != (verify.GenesisTrustRoot{}) {
		t.Fatalf("invalid file fell back to environment: got=%+v err=%v", got, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got, err := loadGenesis(path); err == nil || got != (verify.GenesisTrustRoot{}) {
		t.Fatalf("missing file fell back to environment: got=%+v err=%v", got, err)
	}
}

func captureAnchorRun(t *testing.T, run func() int) (int, string, string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = original; _ = f.Close() }()
	code, out := captureRun(t, run)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return code, out, string(raw)
}

func TestInvalidAnchorStopsAllCommandsBeforeEvidenceOrState(t *testing.T) {
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
		for _, source := range []string{"file", "oversized file", "environment"} {
			for _, existing := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/existing-%t", name, source, existing), func(t *testing.T) {
					clearAnchorEnvironment(t)
					// Evidence is deliberately absent: malformed anchors must fail first.
					dir := t.TempDir()
					statePath := filepath.Join(dir, "state.json")
					before := []byte("existing state must remain untouched")
					if existing {
						if err := os.WriteFile(statePath, before, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					args := []string{"--state", statePath, "--show-context"}
					if source == "environment" {
						t.Setenv(anchorEnvNames[2], "12")
					} else {
						path := filepath.Join(dir, "anchor.json")
						body := "{}"
						if source == "oversized file" {
							body += strings.Repeat(" ", verify.MaxGenesisConfigBytes)
						}
						if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
							t.Fatal(err)
						}
						args = append(args, "--genesis-config", path)
					}
					if name == "watch" {
						args = append(args, "--peers", server.URL)
					} else {
						args = append(args, filepath.Join(dir, "absent-bundle.json"))
					}
					code, out, diagnostics := captureAnchorRun(t, func() int { return run(args) })
					if code != 70 || out != "" || !strings.HasPrefix(diagnostics, "genesis: ") || strings.Contains(diagnostics, "verification_context:") {
						t.Fatalf("invalid anchor reached verification: code=%d out=%s diagnostics=%s", code, out, diagnostics)
					}
					if after, err := os.ReadFile(statePath); existing {
						if err != nil || !bytes.Equal(before, after) {
							t.Fatalf("existing state changed: %v", err)
						}
					} else if !os.IsNotExist(err) {
						t.Fatalf("failed setup created state: %v", err)
					}
					if requests.Load() != 0 {
						t.Fatal("invalid anchor triggered an RPC request")
					}
				})
			}
		}
	}
}

func TestEnvironmentAnchorVerifiesAndPersists(t *testing.T) {
	bundlePath, configPath := stateValueBundleFromLongChain(t, 6, nil)
	anchor, err := verify.LoadGenesisFromConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	setAnchorEnvironment(t, anchor)
	statePath := filepath.Join(t.TempDir(), "state.json")
	code, out := captureRun(t, func() int {
		return runVerifyHeaders([]string{"--state", statePath, "--show-context", bundlePath})
	})
	if code != 0 || !strings.Contains(out, "ACCEPT") || readCLIContext(t, out).Anchor != anchor {
		t.Fatalf("complete environment override failed: code=%d out=%s", code, out)
	}
	if state, err := verify.LoadTrustedState(statePath, anchor, verify.VerifyOptions{Policy: verify.DefaultPolicy()}); err != nil || state.Empty() {
		t.Fatalf("verified environment anchor did not persist: %v", err)
	}
}
