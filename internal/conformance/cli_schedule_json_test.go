package conformance_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestCompiledCLIRejectsAmbiguousScheduleBeforeState(t *testing.T) {
	binary := buildQueryCLIs(t, "zenon-spv")["zenon-spv"]
	c, headers, policy := transitionFixture(t)
	entries := make([]verify.ProducerEntry, len(headers))
	for i, h := range headers {
		entries[i] = verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix,
			ProducingAddr: chain.PubKeyToAddress(h.PublicKey)}
	}
	schedule, err := verify.NewProducerSchedule(c.Transition.Anchor.ChainID,
		[]verify.ProducerCoverage{{FromHeight: 2001, ThroughHeight: 2006}}, entries,
		[]string{"PRIVATE_SCHEDULE_PEER"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(schedule)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	anchor := writeCLIJSON(t, dir, "anchor.json", c.Transition.Anchor)
	profile := writeCLIJSON(t, dir, "profile.json", policy.ProtocolProfile)
	bundle := writeCLIJSON(t, dir, "bundle.json", proof.HeaderBundle{
		Version: 1, ChainID: c.Transition.Anchor.ChainID, ClaimedGenesis: c.Transition.Anchor.HeaderHash, Headers: headers})
	var calls atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer peer.Close()
	for name, input := range map[string]string{
		"replaced chain":    `{"chain_id":999,` + string(raw[1:]),
		"replaced producer": strings.Replace(string(raw), `"producing_addr":`, `"producing_addr":"`+strings.Repeat("00", 20)+`","producing_addr":`, 1),
		"null coverage":     strings.Replace(string(raw), `"from_height":2001`, `"from_height":null`, 1),
		"unknown field":     `{"PRIVATE_FIELD":"PRIVATE_VALUE",` + string(raw[1:]),
	} {
		t.Run(name, func(t *testing.T) {
			for _, command := range []string{"verify-headers", "verify-commitment", "verify-segment", "verify-state-value", "inspect-state", "watch"} {
				t.Run(command, func(t *testing.T) {
					dir := t.TempDir()
					statePath, schedulePath := filepath.Join(dir, "PRIVATE_STATE.json"), filepath.Join(dir, "PRIVATE_SCHEDULE.json")
					if err := os.WriteFile(statePath, []byte("PRIVATE_STATE_NOT_LOADED"), 0o600); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(protectCLIState(t, statePath))
					if err := os.WriteFile(schedulePath, []byte(input), 0o600); err != nil {
						t.Fatal(err)
					}
					args := []string{command, "--json", "--genesis-config", anchor, "--protocol-profile", profile, "--schedule", schedulePath, "--state", statePath}
					switch command {
					case "watch":
						args = append(args, "--once", "--rpc", peer.URL+"/PRIVATE_RPC_PATH")
					case "inspect-state":
					default:
						args = append(args, bundle)
					}
					result := runQueryCLI(t, binary, args...)
					if result.code != 70 {
						t.Fatalf("invalid schedule exit: %d", result.code)
					}
					switch command {
					case "watch":
						if len(result.stdout) != 0 || string(result.stderr) != "schedule: operation failed\n" {
							t.Fatal("watch started or failed outside schedule setup")
						}
					case "inspect-state":
						var report cliInspectionReport
						if err := json.Unmarshal(result.stdout, &report); err != nil || len(result.stderr) != 0 ||
							report.Error == nil || report.Error.Stage != "schedule" || report.ExitCode != 70 || report.Window != nil || report.Context != nil {
							t.Fatal("inspection read state or lost the schedule failure stage")
						}
					default:
						report := checkProcessReport(t, result, 70, "")
						if report.Error == nil || report.Error.Stage != "schedule" || report.Persistence != "not_attempted" ||
							report.Context != nil || report.Tip.Height != 0 || len(report.Results) != 0 {
							t.Fatal("verification reached state or lost the schedule failure stage")
						}
					}
					if bytes.Contains(result.stdout, []byte("PRIVATE")) || bytes.Contains(result.stderr, []byte("PRIVATE")) {
						t.Fatal("schedule failure disclosed a private path or value")
					}
					if _, err := os.Stat(statePath + ".lock"); !os.IsNotExist(err) {
						t.Fatal("invalid schedule reached writer locking")
					}
				})
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid schedule reached RPC")
	}
}
