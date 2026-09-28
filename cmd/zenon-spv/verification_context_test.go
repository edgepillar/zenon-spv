package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func readCLIContext(t *testing.T, output string) verify.VerificationContext {
	t.Helper()
	var c verify.VerificationContext
	count := 0
	for _, line := range strings.Split(output, "\n") {
		if raw, ok := strings.CutPrefix(line, "verification_context: "); ok {
			if err := json.Unmarshal([]byte(raw), &c); err != nil {
				t.Fatal(err)
			}
			count++
		}
	}
	if count != 1 || c.SchemaVersion != 1 || c.Fingerprint == nil {
		t.Fatalf("expected exactly one initialized context, got %d", count)
	}
	return c
}

func TestShowContextAllCommandsPreserveOutcomes(t *testing.T) {
	for name, run := range map[string]func([]string) int{
		"headers": runVerifyHeaders, "commitment": runVerifyCommitment,
		"segment": runVerifySegment, "state-value": runVerifyStateValue,
	} {
		t.Run(name, func(t *testing.T) {
			bundlePath, genesisPath := stateValueBundleFromLongChain(t, 6, nil)
			for _, invalid := range []bool{false, true} {
				if invalid {
					bundle, err := proof.LoadHeaderBundleBounded(bundlePath, verify.DefaultMaxBundleBytes)
					if err != nil {
						t.Fatal(err)
					}
					bundle.Headers[0].Signature[0] ^= 1
					encoded, err := proof.MarshalHeaderBundleJSON(bundle)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(bundlePath, encoded, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				code, plain := captureRun(t, func() int {
					return run([]string{"--genesis-config", genesisPath, bundlePath})
				})
				withCode, output := captureRun(t, func() int {
					return run([]string{"--genesis-config", genesisPath, "--show-context", bundlePath})
				})
				if withCode != code || strings.Contains(plain, "verification_context:") {
					t.Fatal("context reporting changed outcome or default output")
				}
				readCLIContext(t, output)
				if invalid && (code != 1 || strings.Contains(output, "ACCEPT")) {
					t.Fatal("context reporting granted evidence to an invalid signature")
				}
			}
		})
	}
}

func TestShowContextCapturesSettingsWithoutPrivateMetadata(t *testing.T) {
	bundlePath, genesisPath := stateValueBundleFromLongChain(t, 6, nil)
	bundle, err := proof.LoadHeaderBundleBounded(bundlePath, verify.DefaultMaxBundleBytes)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := verify.LoadGenesisFromConfig(genesisPath)
	if err != nil {
		t.Fatal(err)
	}
	profile := &verify.ProtocolProfile{Version: 1, Anchor: anchor, ValidThrough: bundle.Headers[5].Height + 10,
		Source: "PRIVATE_AUDIT_LABEL https://private.invalid/observation"}
	entries := make([]verify.ProducerEntry, len(bundle.Headers))
	for i, h := range bundle.Headers {
		entries[i] = verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.PublicKey)}
	}
	schedule, err := verify.NewProducerSchedule(anchor.ChainID,
		[]verify.ProducerCoverage{{FromHeight: entries[0].Height, ThroughHeight: entries[5].Height}}, entries,
		[]string{"PRIVATE_PEER"}, map[string]uint64{"PRIVATE_PEER": entries[5].Height})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	profilePath, schedulePath := filepath.Join(dir, "profile.json"), filepath.Join(dir, "schedule.json")
	for path, value := range map[string]any{profilePath: profile, schedulePath: schedule} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, output := captureRun(t, func() int {
		return runVerifyHeaders([]string{"--genesis-config", genesisPath, "--protocol-profile", profilePath,
			"--schedule", schedulePath, "--show-context", bundlePath})
	})
	if code != 0 {
		t.Fatalf("verification failed: %d %s", code, output)
	}
	for _, private := range []string{dir, genesisPath, bundlePath, "PRIVATE_AUDIT_LABEL", "PRIVATE_PEER", "private.invalid"} {
		if strings.Contains(output, private) {
			t.Fatal("private provenance metadata reached successful output")
		}
	}
	policy := verify.DefaultPolicy()
	policy.ProtocolProfile = profile
	state, err := verify.NewVerifiedState(anchor, verify.VerifyOptions{Policy: policy,
		ProducerAuth: verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired, Authorizer: verify.NewScheduleAuthorizer(schedule)}})
	if err != nil {
		t.Fatal(err)
	}
	want, err := state.VerificationContext()
	if err != nil || !reflect.DeepEqual(want, readCLIContext(t, output)) {
		t.Fatalf("CLI reported settings different from its captured API configuration: %v", err)
	}
}
