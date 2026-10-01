package conformance_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Follow the operator guide using shipped executables and one credentialed
// loopback peer. Trust inputs are fixture attestations, not network evidence.
func TestCompiledPinnedOperatorWorkflow(t *testing.T) {
	bins := buildQueryCLIs(t, "zenon-spv", "fetch-bundle")
	c, bundle := contractBatchBundle(t)
	dir := t.TempDir()
	peer := newQueryCLIPeer(t, c, false, bundle.Headers[8])
	// The expected checkpoint comes from the pinned corpus, before collection.
	// This is a fixture trust choice, not authentication by the RPC observation.
	selectedAnchor := verify.GenesisTrustRoot{ChainID: c.Chain.Anchor.ChainID,
		Height: bundle.Headers[0].Height, HeaderHash: bundle.Headers[0].HeaderHash}
	bundle.ClaimedGenesis = selectedAnchor.HeaderHash
	anchor := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", selectedAnchor)
	profile := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", verify.ProtocolProfile{
		Version: 1, Anchor: selectedAnchor, ValidThrough: 4010, Source: "PRIVATE_PROFILE_SOURCE"})
	var entries []verify.ProducerEntry
	for _, h := range bundle.Headers {
		entries = append(entries, verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
	}
	schedule, err := verify.NewProducerSchedule(c.Chain.Anchor.ChainID,
		[]verify.ProducerCoverage{{FromHeight: 4001, ThroughHeight: 4009}}, entries,
		[]string{"PRIVATE_SCHEDULE_PEER"}, map[string]uint64{"PRIVATE_SCHEDULE_PEER": 4009})
	if err != nil {
		t.Fatal(err)
	}
	schedulePath := writeCLIJSON(t, dir, "PRIVATE_SCHEDULE.json", schedule)
	config := []string{"--json", "--genesis-config", anchor, "--protocol-profile", profile, "--window", "low"}
	withSchedule := append(slices.Clone(config), "--schedule", schedulePath)
	statePath := filepath.Join(dir, "PRIVATE_STATE.json")
	var context verify.VerificationContext
	t.Run("record build and trust settings before state or RPC", func(t *testing.T) {
		for _, bin := range bins {
			result := runQueryCLI(t, bin, "version", "--json")
			if result.code != 0 || !json.Valid(result.stdout) || len(result.stderr) != 0 {
				t.Fatal("build identity report failed")
			}
			assertOperatorPrivacy(t, result, dir)
		}
		result := runQueryCLI(t, bins["zenon-spv"], append([]string{"inspect-config"}, withSchedule...)...)
		var report struct {
			SchemaVersion   int `json:"schema_version"`
			Command, Status string
			ExitCode        int                        `json:"exit_code"`
			Context         verify.VerificationContext `json:"verification_context"`
		}
		decoder := json.NewDecoder(bytes.NewReader(result.stdout))
		if result.code != 0 || len(result.stderr) != 0 || decoder.Decode(&report) != nil || decoder.Decode(new(any)) != io.EOF ||
			report.SchemaVersion != 1 || report.Command != "inspect-config" || report.Status != "configured" || report.ExitCode != 0 ||
			report.Context.Anchor != selectedAnchor || report.Context.Producer.Mode != "Required" || report.Context.Fingerprint == nil {
			t.Fatal("configuration did not record the explicit trust selection")
		}
		context = report.Context
		assertOperatorPrivacy(t, result, dir)
		for _, path := range []string{statePath, statePath + ".lock"} {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("configuration inspection created state or writer ownership")
			}
		}
		if peer.calls.Load() != 0 {
			t.Fatal("configuration inspection contacted the peer")
		}
	})
	if context.Fingerprint == nil {
		t.Fatal("operator workflow requires a configuration fingerprint")
	}
	pin := hex.EncodeToString(context.Fingerprint[:])
	common := append(slices.Clone(withSchedule), "--expect-context", pin, "--state", statePath)
	seedPath := filepath.Join(dir, "PRIVATE_SEED.json")
	t.Run("initialize an explicitly anchored state", func(t *testing.T) {
		collected := runQueryCLI(t, bins["fetch-bundle"], "--peers", peer.url, "--quorum", "1",
			"--height", "4008", "--count", "7", "--out", seedPath)
		if collected.code != 0 || len(collected.stdout) != 0 {
			t.Fatal("initial candidate collection failed")
		}
		result := runQueryCLI(t, bins["zenon-spv"], append([]string{"verify-headers"}, append(slices.Clone(common), seedPath)...)...)
		r := checkProcessReport(t, result, 0, "ACCEPT")
		if r.Persistence != "saved" || r.Tip.Height != 4008 || r.Tip.Hash != bundle.Headers[7].HeaderHash || r.Context == nil || *r.Context.Fingerprint != *context.Fingerprint {
			t.Fatal("initialization did not persist the pinned configuration's expected tip")
		}
		assertOperatorPrivacy(t, result, dir)
	})
	proofOnly := bundle
	proofOnly.Headers = nil
	proofPath := writeCLIJSON(t, dir, "PRIVATE_PROOF.json", proofOnly)
	t.Run("drift stops every state command before RPC or writes", func(t *testing.T) {
		check := protectCLIState(t, statePath)
		before := peer.calls.Load()
		for _, drift := range []string{"drop schedule", "change window"} {
			changed := slices.Clone(common)
			if drift == "drop schedule" {
				changed = append(slices.Clone(config), "--expect-context", pin, "--state", statePath)
			} else {
				changed = append(changed, "--window", "high")
			}
			for _, command := range []string{"verify-headers", "verify-commitment", "verify-segment", "verify-state-value", "inspect-state", "watch"} {
				args := append([]string{command}, changed...)
				switch command {
				case "watch":
					args = append(args, "--once", "--rpc", peer.url)
				case "inspect-state":
				case "verify-headers":
					args = append(args, seedPath)
				default:
					args = append(args, "--retained-only", proofPath)
				}
				result := runQueryCLI(t, bins["zenon-spv"], args...)
				if result.code != 70 {
					t.Fatalf("%s did not stop for %s", command, drift)
				}
				if command == "watch" {
					if len(result.stdout) != 0 || string(result.stderr) != "watch: operation failed\n" {
						t.Fatal("pin mismatch emitted watch startup or raw diagnostics")
					}
				} else {
					var r struct {
						Error   struct{ Stage string }
						Outcome *string
						Results []any
					}
					if len(result.stderr) != 0 || json.Unmarshal(result.stdout, &r) != nil || r.Error.Stage != "context_pin" || r.Outcome != nil || len(r.Results) != 0 {
						t.Fatal("pin mismatch became a proof result")
					}
				}
				assertOperatorPrivacy(t, result, dir)
				check()
			}
		}
		if peer.calls.Load() != before {
			t.Fatal("drifted verification settings reached the network")
		}
	})
	for _, event := range []string{"advanced", "caught_up"} {
		t.Run("bounded watch process "+event, func(t *testing.T) {
			args := append([]string{"watch"}, common...)
			args = append(args, "--once", "--rpc", peer.url, "--safety-margin", "1", "--batch-size", "1")
			result := runQueryCLI(t, bins["zenon-spv"], args...)
			decoder := json.NewDecoder(bytes.NewReader(result.stdout))
			var startup, tick cliWatchEvent
			if result.code != 0 || len(result.stderr) != 0 || decoder.Decode(&startup) != nil || decoder.Decode(&tick) != nil || decoder.Decode(new(any)) != io.EOF ||
				startup.Event != "started" || tick.Event != event || tick.Error != nil || tick.StateTip.Height != 4009 || tick.StateTip.Hash != bundle.Headers[8].HeaderHash ||
				startup.Context.Fingerprint == nil || tick.Context.Fingerprint == nil || *startup.Context.Fingerprint != *context.Fingerprint || *tick.Context.Fingerprint != *context.Fingerprint {
				t.Fatalf("bounded watch or restart lost the pinned settings, event, or tip: exit=%d startup=%s event=%s tip=%d error=%+v", result.code, startup.Event, tick.Event, tick.StateTip.Height, tick.Error)
			}
			if event == "advanced" && (tick.Persistence != "saved" || tick.Verification == nil || tick.Verification.Outcome != "ACCEPT") {
				t.Fatal("watch confused accepted evidence with completed persistence")
			}
			assertOperatorPrivacy(t, result, dir)
		})
	}
	check := protectCLIState(t, statePath)
	defer check()
	t.Run("collect then query retained evidence", func(t *testing.T) {
		candidate := filepath.Join(dir, "PRIVATE_CANDIDATE.json")
		result := runQueryCLI(t, bins["fetch-bundle"], "--peers", peer.url, "--quorum", "1", "--height", "4009", "--count", "8",
			"--proof-only", "--segments", c.Segments[0].RPCAddress+":1-5", "--out", candidate)
		if result.code != 0 || len(result.stdout) != 0 || !bytes.Contains(result.stderr, []byte("Verification required:")) {
			t.Fatal("collection failed or claimed verification")
		}
		// Collection diagnostics may include the operator-selected output path;
		// keep them private. Only verification reports are shareable records.
		for _, command := range []string{"verify-commitment", "verify-segment"} {
			args := append([]string{command}, common...)
			result := runQueryCLI(t, bins["zenon-spv"], append(args, "--retained-only", candidate)...)
			assertProcessInclusions(t, checkProcessReport(t, result, 0, "ACCEPT"), bundle)
			assertOperatorPrivacy(t, result, dir)
			check()
		}
	})
	t.Run("inspect without turning a retained snapshot into proof", func(t *testing.T) {
		result := runQueryCLI(t, bins["zenon-spv"], append([]string{"inspect-state"}, common...)...)
		var r struct {
			Status      string
			Persistence string
			Outcome     *string
			Window      verify.RetainedSummary `json:"retained_window"`
		}
		if result.code != 0 || len(result.stderr) != 0 || json.Unmarshal(result.stdout, &r) != nil || r.Status != "inspected" || r.Persistence != "read_only" || r.Outcome != nil || r.Window.Tip.Height != 4009 {
			t.Fatal("inspection changed the read-only snapshot boundary")
		}
		assertOperatorPrivacy(t, result, dir)
		check()
	})
}

func assertOperatorPrivacy(t *testing.T, result queryCLIResult, dir string) {
	t.Helper()
	for _, output := range [][]byte{result.stdout, result.stderr} {
		if bytes.Contains(output, []byte("PRIVATE")) || bytes.Contains(output, []byte(dir)) {
			t.Fatal("operator report disclosed private paths, labels, or credentials")
		}
	}
}
