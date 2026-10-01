package conformance_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestCompiledScheduleExportAndVerification(t *testing.T) {
	bins := buildQueryCLIs(t, "derive-producer-schedule", "zenon-spv")
	c, headers, policy := transitionFixture(t)
	var requests atomic.Int64
	urls := make([]string, 3)
	for i := range urls {
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			var req struct {
				ID     json.RawMessage
				Method string
				Params []uint64
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
				return
			}
			var result any
			switch req.Method {
			case "ledger.getFrontierMomentum":
				result = c.Transition.Vectors[5].Momentum
			case "ledger.getMomentumsByHeight":
				if len(req.Params) != 2 || req.Params[0] < 2001 || req.Params[0] > 2006 || req.Params[1] != 2 || req.Params[0]+req.Params[1] > 2007 {
					t.Error("unexpected schedule batch")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				start := req.Params[0] - 2001
				result = map[string]any{"list": []json.RawMessage{c.Transition.Vectors[start].Momentum, c.Transition.Vectors[start+1].Momentum}}
			default:
				t.Error("unexpected schedule method")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}); err != nil {
				t.Error(err)
			}
		}))
		t.Cleanup(peer.Close)
		urls[i] = strings.Replace(peer.URL, "://", "://PRIVATE_USER:PRIVATE_PASSWORD@", 1) + "/PRIVATE_PATH?token=PRIVATE_TOKEN"
	}
	dir := t.TempDir()
	output := filepath.Join(dir, "PRIVATE_SCHEDULE.json")
	if err := os.WriteFile(output, []byte("previous schedule"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"--peers", strings.Join(urls, ","), "--from", "2001", "--through", "2006", "--batch-size", "2",
		"--chain-id", strconv.FormatUint(c.Transition.Anchor.ChainID, 10), "--out", output}
	result := runQueryCLI(t, bins["derive-producer-schedule"], args...)
	if result.code != 0 || len(result.stdout) != 0 || !bytes.Contains(result.stderr, []byte("wrote schedule: 6 entries")) || requests.Load() != 12 {
		t.Fatal("schedule command did not finish the bounded observation range")
	}
	if bytes.Contains(result.stderr, []byte("PRIVATE")) {
		t.Fatal("schedule completion disclosed private provenance or its output path")
	}
	schedule, err := verify.LoadProducerSchedule(output)
	if err != nil || len(schedule.Entries) != 6 || len(schedule.SourcePeers) != 3 {
		t.Fatalf("exported schedule failed the strict loader: %v", err)
	}
	for i, h := range headers {
		if schedule.Entries[i].Height != h.Height || schedule.Entries[i].TimestampUnix != h.TimestampUnix ||
			schedule.Entries[i].ProducingAddr != chain.PubKeyToAddress(h.PublicKey) {
			t.Fatal("schedule changed a node-derived observation")
		}
	}
	for _, url := range urls {
		if schedule.SourceHeights[url] != 2006 {
			t.Fatal("private artifact lost configured provenance metadata")
		}
	}
	info, err := os.Stat(output)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatal("schedule export did not restrict file permissions")
	}
	anchor := writeCLIJSON(t, dir, "anchor.json", c.Transition.Anchor)
	profile := writeCLIJSON(t, dir, "profile.json", policy.ProtocolProfile)
	bundle := writeCLIJSON(t, dir, "bundle.json", proof.HeaderBundle{Version: 1, ChainID: c.Transition.Anchor.ChainID,
		ClaimedGenesis: c.Transition.Anchor.HeaderHash, Headers: headers})
	state := filepath.Join(dir, "state.json")
	report := checkProcessReport(t, runQueryCLI(t, bins["zenon-spv"], "verify-headers", "--json", "--genesis-config", anchor,
		"--protocol-profile", profile, "--schedule", output, "--state", state, bundle), 0, "ACCEPT")
	if report.Persistence != "saved" || report.Tip.Height != 2006 || len(report.Results) != 1 ||
		!slices.Contains(report.Results[0].Proven, verify.GuaranteeProducerAuthorization) ||
		!slices.Contains(report.Results[0].Trust, verify.TrustExternalProducerSchedule) {
		t.Fatal("exported schedule did not authorize the configured observation range")
	}
	unchanged := protectCLIState(t, output)
	t.Cleanup(unchanged)
	for _, extra := range [][]string{{"--out", filepath.Join(dir, "PRIVATE_MISSING", "schedule.json")}, {"PRIVATE_POSITIONAL_ARGUMENT"}} {
		invocation := append(append([]string{}, args...), extra...)
		result := runQueryCLI(t, bins["derive-producer-schedule"], invocation...)
		if result.code != 1 || len(result.stdout) != 0 || requests.Load() != 12 || bytes.Contains(result.stderr, []byte("PRIVATE")) {
			t.Fatal("invalid exporter invocation reached RPC or reported success")
		}
		unchanged()
	}
}
