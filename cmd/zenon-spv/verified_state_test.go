package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestVerifyHeadersCLI_ReportsTrustedResumeSeparately(t *testing.T) {
	bundlePath, genesisPath := stateValueBundleFromLongChain(t, 12, nil)
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := proof.UnmarshalHeaderBundleJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	all := bundle.Headers
	statePath := filepath.Join(t.TempDir(), "state.json")
	var fingerprint chain.Hash
	for batch := range 2 {
		bundle.Headers = all[batch*6 : (batch+1)*6]
		encoded, err := proof.MarshalHeaderBundleJSON(bundle)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bundlePath, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		code, output := captureRun(t, func() int {
			return runVerifyHeaders([]string{"--genesis-config", genesisPath, "--state", statePath, "--show-context", bundlePath})
		})
		if code != 0 || !strings.Contains(output, string(verify.TrustConfiguredAnchor)) {
			t.Fatalf("batch %d: exit=%d output=%s", batch, code, output)
		}
		if got := strings.Contains(output, string(verify.TrustPersistedState)); got != (batch == 1) {
			t.Fatalf("batch %d: persisted-state trust=%v", batch, got)
		}
		context := readCLIContext(t, output)
		if batch == 0 {
			fingerprint = *context.Fingerprint
		} else if *context.Fingerprint != fingerprint {
			t.Fatal("resume changed the captured settings fingerprint")
		}
	}
}

func TestVerifyHeadersCLI_ResumeAuthorizationPreservesOutcome(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   int
		reason verify.ReasonCode
	}{
		{"unauthorized", 1, verify.ReasonUnauthorizedProducer},
		{"uncovered", 2, verify.ReasonProducerSetUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundlePath, genesisPath := stateValueBundleFromLongChain(t, 12, nil)
			raw, err := os.ReadFile(bundlePath)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := proof.UnmarshalHeaderBundleJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
			all := bundle.Headers
			statePath := filepath.Join(t.TempDir(), "state.json")
			writeBatch := func(headers []chain.Header) {
				t.Helper()
				bundle.Headers = headers
				encoded, err := proof.MarshalHeaderBundleJSON(bundle)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(bundlePath, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeBatch(all[:6])
			if code, _ := captureRun(t, func() int {
				return runVerifyHeaders([]string{"--genesis-config", genesisPath, "--state", statePath, bundlePath})
			}); code != 0 {
				t.Fatalf("initial verification failed: %d", code)
			}
			before, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatal(err)
			}
			entries := make([]verify.ProducerEntry, len(all))
			for i, h := range all {
				entries[i] = verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix,
					ProducingAddr: chain.PubKeyToAddress(h.PublicKey)}
			}
			if tc.name == "uncovered" {
				entries = entries[1:]
			} else {
				entries[0].ProducingAddr = chain.Address{1}
			}
			coverage := []verify.ProducerCoverage{{FromHeight: entries[0].Height, ThroughHeight: entries[len(entries)-1].Height}}
			schedule, err := verify.NewProducerSchedule(bundle.ChainID, coverage, entries, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			scheduleRaw, err := json.Marshal(schedule)
			if err != nil {
				t.Fatal(err)
			}
			schedulePath := filepath.Join(t.TempDir(), "schedule.json")
			if err := os.WriteFile(schedulePath, scheduleRaw, 0o600); err != nil {
				t.Fatal(err)
			}
			writeBatch(all[6:])
			code, output := captureRun(t, func() int {
				return runVerifyHeaders([]string{"--genesis-config", genesisPath, "--state", statePath, "--schedule", schedulePath, bundlePath})
			})
			if code != tc.code || !strings.Contains(output, tc.reason.String()) || strings.Contains(output, "ACCEPT") {
				t.Fatalf("expected exit=%d reason=%s without ACCEPT, got exit=%d output=%s", tc.code, tc.reason, code, output)
			}
			after, err := os.ReadFile(statePath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("failed authorization changed persisted state: %v", err)
			}
		})
	}
}
