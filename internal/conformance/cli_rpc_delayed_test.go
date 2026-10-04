package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// The ordinary joined command sees unmodified node-derived v1/v2 envelopes,
// except for one declared tamper control. All trust attestations are synthetic;
// one loopback operator supplies no independent activation or election evidence.
func TestCompiledRPCObserverDelayedInclusion(t *testing.T) {
	bins := buildQueryCLIs(t, "fetch-bundle", "zenon-spv", "consume-query-report", "observe-block")
	hashes := make(map[string]string)
	for name, path := range bins {
		digest := sha256.Sum256(readCLIFile(t, path))
		hashes[name] = hex.EncodeToString(digest[:])
	}
	c, bundle := delayedInclusionBundle(t)
	opts, schedule := delayedOptions(t, c)
	dir := t.TempDir()
	anchorPath := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", c.Chain.Anchor)
	profilePath := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", opts.Policy.ProtocolProfile)
	schedulePath := writeCLIJSON(t, dir, "PRIVATE_SCHEDULE.json", schedule)
	private := filepath.Join(dir, "PRIVATE_RECORDS")
	if os.Mkdir(private, 0o700) != nil {
		t.Fatal("cannot prepare protected record parent")
	}
	var guards []func()
	for _, path := range []string{anchorPath, profilePath, schedulePath} {
		guards = append(guards, protectCLIState(t, path))
	}
	states := make(map[uint64]string)
	var pin string
	// Select and protect every state/context before the joined command collects
	// a candidate. Each state comes from the same fixed corpus and policy.
	for _, tip := range []uint64{5016, 5017, 5018, 5019} {
		state, err := verify.NewVerifiedState(c.Chain.Anchor, opts)
		if err != nil {
			t.Fatal("cannot initialize explicit delayed settings")
		}
		accepted, state := state.Extend(bundle.Headers[:tip-c.Chain.Anchor.Height])
		if accepted.Outcome != verify.OutcomeAccept {
			t.Fatal("selected delayed headers refused")
		}
		context, err := state.VerificationContext()
		if err != nil || context.Fingerprint == nil {
			t.Fatal("missing selected context")
		}
		selected := hex.EncodeToString(context.Fingerprint[:])
		if pin != "" && pin != selected {
			t.Fatal("fixed policy changed context across retained tips")
		}
		pin = selected
		path := filepath.Join(dir, "PRIVATE_STATE_"+strconv.FormatUint(tip, 10)+".json")
		if state.Save(path) != nil {
			t.Fatal("cannot preserve selected retained state")
		}
		states[tip] = path
		guards = append(guards, protectCLIState(t, path))
	}
	var signed, embedded int
	for index, segment := range c.Segments {
		if segment.Address.IsEmbeddedAddress() {
			embedded = index
		} else {
			signed = index
		}
	}
	if signed == embedded || len(c.Segments) != 2 {
		t.Fatal("missing distinct signed and embedded selections")
	}
	cases := []struct {
		name                       string
		segments                   []int
		stateTip, collectTip, tip  uint64
		requireSignature           bool
		tamperV2                   bool
		outer, collector, verifier int
		consumer                   *int64
		category                   string
	}{
		{"mixed content at exact depth", []int{0, 1}, 5017, 5017, 5017, false, false, 0, 0, 0, int64Pointer(0), ""},
		{"signed segment requires signature", []int{signed}, 5017, 5017, 5017, true, false, 0, 0, 0, int64Pointer(0), ""},
		{"embedded inclusion supplies no signature", []int{embedded}, 5017, 5017, 5017, true, false, 2, 0, 0, int64Pointer(2), "guarantee_mismatch"},
		{"insufficient depth stops consumption", []int{signed}, 5016, 5016, 5016, true, false, 2, 0, 2, nil, "process_failure"},
		{"fetched evicted evidence cannot restore state", []int{signed}, 5019, 5019, 5019, true, false, 2, 0, 2, nil, "process_failure"},
		{"newer collection cannot advance state", []int{signed}, 5017, 5018, 5018, true, false, 2, 0, 0, int64Pointer(2), "report_mismatch"},
		{"changed v2 price stops collection", []int{signed}, 5017, 5017, 5017, true, true, 2, 1, -1, nil, "process_failure"},
		{"recovery preserves mixed selection", []int{0, 1}, 5018, 5018, 5018, false, false, 0, 0, 0, int64Pointer(0), ""},
	}
	// Expected identities come directly from the fixed node account corpus,
	// never from the proof-only collection performed by this application.
	expectedPaths := make([]string, len(cases))
	for index, test := range cases {
		var targets []any
		for segmentIndex, corpusIndex := range test.segments {
			for blockIndex, vector := range c.Segments[corpusIndex].Vectors {
				targets = append(targets, map[string]any{"scope": "segment", "index": segmentIndex,
					"block_index": blockIndex, "account_header": vector.Block.AccountHeader()})
			}
		}
		required := []string{"CONTENT_INCLUSION"}
		if test.requireSignature {
			required = append(required, "SIGNATURE_AUTHENTICITY")
		}
		header := bundle.Headers[test.tip-c.Chain.Anchor.Height-1]
		expectations := map[string]any{"schema_version": 1, "command": "verify-segment", "context_fingerprint": pin,
			"verification_tip": map[string]any{"height": header.Height, "hash": header.HeaderHash},
			"targets":          targets, "required_guarantees": required,
			"allowed_trust_assumptions": []string{"TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_RETAINED_WINDOW_DEPTH", "TRUST_EXTERNAL_PROTOCOL_PROFILE", "TRUST_EXTERNAL_PRODUCER_SCHEDULE"}}
		expectedPaths[index] = writeCLIJSON(t, dir, "PRIVATE_EXPECTATIONS_"+strconv.Itoa(index)+".json", expectations)
		guards = append(guards, protectCLIState(t, expectedPaths[index]))
	}
	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			selected := c
			if test.tamperV2 {
				selected.Chain.Vectors = slices.Clone(c.Chain.Vectors)
				vector := &selected.Chain.Vectors[10] // v2 at height 5011
				var rpc map[string]json.RawMessage
				if vector.Header.Height != 5011 || json.Unmarshal(vector.Momentum, &rpc) != nil || rpc["nextFusionPrice"] == nil {
					t.Fatal("missing node-derived v2 price field")
				}
				rpc["nextFusionPrice"] = json.RawMessage(strconv.FormatUint(vector.Header.NextFusionPrice+1, 10))
				vector.Momentum = marshalCLIValue(t, rpc)
			}
			peer := newDelayedCLIPeer(t, selected)
			var segments []string
			for _, corpusIndex := range test.segments {
				segments = append(segments, c.Segments[corpusIndex].RPCAddress+":1-3")
			}
			// RPC envelopes begin immediately after the anchor. Keep the
			// collector checkpoint in that corpus while retention stays K=16.
			collectCount := min(uint64(16), test.collectTip-c.Chain.Anchor.Height-1)
			args := []string{"--collector", bins["fetch-bundle"], "--collector-sha256", hashes["fetch-bundle"],
				"--rpc", peer.url, "--height", strconv.FormatUint(test.collectTip, 10), "--count", strconv.FormatUint(collectCount, 10),
				"--segments", strings.Join(segments, ","),
				"--verifier", bins["zenon-spv"], "--verifier-sha256", hashes["zenon-spv"],
				"--consumer", bins["consume-query-report"], "--consumer-sha256", hashes["consume-query-report"],
				"--command", "verify-segment", "--genesis-config", anchorPath, "--protocol-profile", profilePath,
				"--schedule", schedulePath, "--state", states[test.stateTip], "--expectations", expectedPaths[index],
				"--private-dir", private, "--expect-context", pin, "--window", "low", "--retain-headers", "16"}
			result := runQueryCLI(t, bins["observe-block"], args...)
			var report struct {
				Version   int                   `json:"schema_version"`
				Status    string                `json:"status"`
				Category  *string               `json:"category"`
				Count     int                   `json:"checked_targets"`
				ElapsedNS int64                 `json:"elapsed_ns"`
				Collector observerProcessRecord `json:"collector"`
				Verifier  observerProcessRecord `json:"verifier"`
				Consumer  observerProcessRecord `json:"consumer"`
			}
			if result.code != test.outer || len(result.stderr) != 0 || json.Unmarshal(result.stdout, &report) != nil ||
				report.Version != 2 || report.ElapsedNS < 0 || len(losslessObject(t, result.stdout)) != 8 ||
				report.Collector.ExitCode == nil || *report.Collector.ExitCode != int64(test.collector) {
				t.Fatal("delayed RPC observation lost actual completion")
			}
			if (report.Verifier.ExitCode == nil) != (test.verifier == -1) ||
				(report.Verifier.ExitCode != nil && *report.Verifier.ExitCode != int64(test.verifier)) ||
				(report.Consumer.ExitCode == nil) != (test.consumer == nil) ||
				(report.Consumer.ExitCode != nil && *report.Consumer.ExitCode != *test.consumer) {
				t.Fatal("later children crossed their collection or verification boundary")
			}
			if test.outer == 0 {
				if report.Status != "matched" || report.Category != nil || report.Count != len(test.segments)*3 {
					t.Fatal("exact selected delayed targets did not match")
				}
			} else if report.Status != "not_matched" || report.Category == nil || *report.Category != test.category || report.Count != 0 {
				t.Fatal("failed delayed observation lost its fixed category")
			}
			wantRequests := int64(1 + len(test.segments))
			if test.tamperV2 {
				wantRequests = 1
			}
			if peer.calls.Load() != wantRequests {
				t.Fatal("fixed-height collection discovered a frontier or retried")
			}
			for _, child := range []observerProcessRecord{report.Collector, report.Verifier, report.Consumer} {
				if child.ElapsedNS < 0 || child.StdoutBytes < 0 || child.StderrBytes < 0 ||
					(child.ExitCode == nil && (child.ElapsedNS != 0 || child.StdoutBytes != 0 || child.StderrBytes != 0)) {
					t.Fatal("child resource observations contradict execution")
				}
			}
			producer := chain.PubKeyToAddress(bundle.Headers[0].PublicKey)
			for _, secret := range []string{"PRIVATE", dir, peer.url, pin, hashes["fetch-bundle"], hashes["zenon-spv"], hashes["consume-query-report"],
				hex.EncodeToString(producer[:])} {
				if bytes.Contains(result.stdout, []byte(secret)) {
					t.Fatal("delayed observation reproduced private data")
				}
			}
			for _, segment := range c.Segments {
				if bytes.Contains(result.stdout, []byte(segment.RPCAddress)) {
					t.Fatal("delayed observation reproduced selected account data")
				}
			}
			for _, guard := range guards {
				guard()
			}
			files, err := os.ReadDir(private)
			if err != nil || len(files) != 0 {
				t.Fatal("delayed observation left private proof or expectation files")
			}
			for _, path := range states {
				if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
					t.Fatal("read-only delayed observation acquired writer ownership")
				}
			}
		})
	}
}

func int64Pointer(value int64) *int64 { return &value }
