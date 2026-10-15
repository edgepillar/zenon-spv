package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Recorded node work and method outcomes supply neither the consumer's original
// signed target nor its independently selected trust and commitment inputs.
func TestCompiledNodeAccountPoWObserver(t *testing.T) {
	bins := buildQueryCLIs(t, "fetch-bundle", "zenon-spv", "consume-query-report", "observe-block")
	hashes := make(map[string]string)
	for name, path := range bins {
		digest := sha256.Sum256(readCLIFile(t, path))
		hashes[name] = hex.EncodeToString(digest[:])
	}
	input := readCLIFile(t, "../testdata/conformance/account-segments.json")
	digest := sha256.Sum256(input)
	if hex.EncodeToString(digest[:]) != "1faca6715c3865bae726a7a07f56ef2c43bd8a5a5c9816f618373312de43b048" {
		t.Fatal("original signed account selection changed")
	}
	c := loadNodeAccountCorpus(t, "account-segments.json")
	user := accountBasicRPCUser(t)
	original := user.Vectors[0].Block
	if original.BlockType != chain.BlockTypeUserSend || original.Height != 1 || original.Difficulty != 0 || original.Nonce != (chain.Nonce{}) {
		t.Fatal("missing independently selected original signed send")
	}
	headers := make([]chain.Header, len(c.Chain.Vectors))
	var entries []verify.ProducerEntry
	for i, vector := range c.Chain.Vectors {
		headers[i] = vector.Header
		entries = append(entries, verify.ProducerEntry{Height: vector.Header.Height, TimestampUnix: vector.Header.TimestampUnix,
			ProducingAddr: chain.PubKeyToAddress(vector.Header.PublicKey)})
	}
	last := headers[len(headers)-1]
	opts := verify.VerifyOptions{Policy: verify.DefaultPolicy()}
	opts.Policy.RetainHeaders = 16
	opts.Policy.ProtocolProfile = &verify.ProtocolProfile{Version: 1, Anchor: c.Chain.Anchor, ValidThrough: last.Height,
		Source: "PRIVATE_POW_OBSERVER_PROFILE"}
	schedule, err := verify.NewProducerSchedule(c.Chain.Anchor.ChainID,
		[]verify.ProducerCoverage{{FromHeight: headers[0].Height, ThroughHeight: last.Height}}, entries, nil, nil)
	if err != nil {
		t.Fatal("cannot select synthetic producer coverage")
	}
	opts.ProducerAuth = verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired, Authorizer: verify.NewScheduleAuthorizer(schedule)}
	initial, err := verify.NewVerifiedState(c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal("cannot prepare the original anchor and explicit policy")
	}
	accepted, retained := initial.Extend(headers)
	if accepted.Outcome != verify.OutcomeAccept {
		t.Fatal("original signed headers did not satisfy the selected policy")
	}
	selectedContext, err := retained.VerificationContext()
	if err != nil || selectedContext.Fingerprint == nil {
		t.Fatal("missing independently selected context")
	}
	pin := hex.EncodeToString(selectedContext.Fingerprint[:])
	dir := t.TempDir()
	anchorPath := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", c.Chain.Anchor)
	profilePath := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", opts.Policy.ProtocolProfile)
	schedulePath := writeCLIJSON(t, dir, "PRIVATE_SCHEDULE.json", schedule)
	statePath := filepath.Join(dir, "PRIVATE_RETAINED_STATE.json")
	initialPath := filepath.Join(dir, "PRIVATE_ANCHOR_STATE.json")
	if retained.Save(statePath) != nil || initial.Save(initialPath) != nil {
		t.Fatal("cannot preserve independently selected states")
	}
	private := filepath.Join(dir, "PRIVATE_RECORDS")
	if os.Mkdir(private, 0o700) != nil {
		t.Fatal("cannot prepare protected observation parent")
	}
	var guards []func()
	for _, path := range []string{anchorPath, profilePath, schedulePath, statePath, initialPath} {
		guards = append(guards, protectCLIState(t, path))
	}
	matched, blocked, coherentChecked := 0, 0, 0
	check := func(t *testing.T, row accountBasicObservation, mode string) {
		t.Helper()
		block := accountPoWBlock(t, row, original)
		wire := row.Wire
		if mode == "coherent-hash" {
			// Change only the claimed hash. RawMessage preserves every uint64
			// and nonce byte, including the unsigned values above 2^63.
			block.BlockHash = block.ComputeHash()
			var fields map[string]json.RawMessage
			if json.Unmarshal(wire, &fields) != nil {
				t.Fatal("cannot read the selected recorded wire object")
			}
			var err error
			if fields["hash"], err = json.Marshal(block.BlockHash); err != nil {
				t.Fatal(err)
			}
			wire, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
		}
		endpoint, calls := basicObserverPeer(t, c, user.RPCAddress, 1, wire, mode == "missing-collected-proof")
		selectedState := statePath
		tip := chain.HashHeight{Height: last.Height, Hash: last.HeaderHash}
		target := original.AccountHeader()
		switch mode {
		case "missing-retained-header":
			selectedState = initialPath
			tip = chain.HashHeight{Height: c.Chain.Anchor.Height, Hash: c.Chain.Anchor.HeaderHash}
		case "wrong-selected-target":
			target = user.Vectors[1].Block.AccountHeader()
		case "wrong-selected-tip":
			h := headers[len(headers)-2]
			tip = chain.HashHeight{Height: h.Height, Hash: h.HeaderHash}
		case "", "missing-collected-proof", "coherent-hash":
		default:
			t.Fatal("unselected account PoW observer control")
		}
		// Select expectations before collection. Node matches and rejections do
		// not change the original send's bounded inclusion/signature claim.
		expectations := map[string]any{"schema_version": 1, "command": "verify-segment", "context_fingerprint": pin,
			"verification_tip":    tip,
			"targets":             []any{map[string]any{"scope": "segment", "index": 0, "block_index": 0, "account_header": target}},
			"required_guarantees": []string{"CONTENT_INCLUSION", "SIGNATURE_AUTHENTICITY"},
			"allowed_trust_assumptions": []string{"TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_RETAINED_WINDOW_DEPTH",
				"TRUST_EXTERNAL_PROTOCOL_PROFILE", "TRUST_EXTERNAL_PRODUCER_SCHEDULE"}}
		expectedPath := writeCLIJSON(t, t.TempDir(), "PRIVATE_EXPECTATIONS.json", expectations)
		guardExpected := protectCLIState(t, expectedPath)
		args := []string{"--collector", bins["fetch-bundle"], "--collector-sha256", hashes["fetch-bundle"],
			"--rpc", endpoint, "--height", strconv.FormatUint(last.Height, 10), "--count", strconv.Itoa(len(headers) - 1),
			"--segments", user.RPCAddress + ":1",
			"--verifier", bins["zenon-spv"], "--verifier-sha256", hashes["zenon-spv"],
			"--consumer", bins["consume-query-report"], "--consumer-sha256", hashes["consume-query-report"],
			"--command", "verify-segment", "--genesis-config", anchorPath, "--protocol-profile", profilePath, "--schedule", schedulePath,
			"--state", selectedState, "--expectations", expectedPath, "--private-dir", private, "--expect-context", pin,
			"--window", "low", "--retain-headers", "16"}
		if mode == "missing-collected-proof" {
			// Omit the original confirming heights; retain every selected signed
			// momentum byte instead of manufacturing a different commitment.
			args = append(args, "--momentum-heights", strconv.FormatUint(last.Height, 10))
		}
		collector, verifier, consumer := int64(0), int64Pointer(0), int64Pointer(0)
		outer, category, count := 0, "", 1
		if row.Profile != originalAccountPoWProfile {
			collector, verifier, consumer = 1, nil, nil
			outer, category, count = 2, "process_failure", 0
		}
		switch mode {
		case "coherent-hash":
			collector, verifier, consumer = 0, int64Pointer(1), nil
			outer, category, count = 2, "process_failure", 0
		case "missing-retained-header", "missing-collected-proof":
			verifier, consumer, outer, category, count = int64Pointer(2), nil, 2, "process_failure", 0
		case "wrong-selected-target":
			consumer, outer, category, count = int64Pointer(2), 2, "target_mismatch", 0
		case "wrong-selected-tip":
			consumer, outer, category, count = int64Pointer(2), 2, "report_mismatch", 0
		}
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
		if result.code != outer || len(result.stderr) != 0 || json.Unmarshal(result.stdout, &report) != nil ||
			report.Version != 2 || report.Count != count || report.ElapsedNS < 0 || len(losslessObject(t, result.stdout)) != 8 ||
			report.Collector.ExitCode == nil || *report.Collector.ExitCode != collector {
			t.Fatalf("recorded PoW input lost its selected process boundary: exit=%d targets=%d collector=%v", result.code, report.Count, report.Collector.ExitCode)
		}
		for _, child := range []struct {
			got  observerProcessRecord
			want *int64
		}{{report.Verifier, verifier}, {report.Consumer, consumer}} {
			if (child.got.ExitCode == nil) != (child.want == nil) || child.want != nil && *child.got.ExitCode != *child.want {
				t.Fatalf("later child exit differs: got=%s want=%s", marshalCLIValue(t, child.got.ExitCode), marshalCLIValue(t, child.want))
			}
		}
		if outer == 0 {
			if report.Status != "matched" || report.Category != nil {
				t.Fatal("original independently selected signed send did not match")
			}
		} else if report.Status != "not_matched" || report.Category == nil || *report.Category != category {
			t.Fatal("failed PoW observation lost its selected refusal category")
		}
		if collector != 0 && report.Collector.StdoutBytes != 0 {
			t.Fatal("failed PoW collection published a partial bundle")
		}
		wantCalls := int32(2)
		if mode == "missing-collected-proof" {
			wantCalls = 3
		}
		if calls.Load() != wantCalls {
			t.Fatal("collection retried, selected a frontier or omitted a request")
		}
		for _, child := range []observerProcessRecord{report.Collector, report.Verifier, report.Consumer} {
			if child.ElapsedNS < 0 || child.StdoutBytes < 0 || child.StderrBytes < 0 ||
				child.ExitCode == nil && (child.ElapsedNS != 0 || child.StdoutBytes != 0 || child.StderrBytes != 0) {
				t.Fatal("resource fields contradict actual child execution")
			}
		}
		for _, secret := range []string{"PRIVATE", endpoint, dir, pin, user.RPCAddress, hashes["fetch-bundle"], hashes["zenon-spv"], hashes["consume-query-report"]} {
			if bytes.Contains(result.stdout, []byte(secret)) {
				t.Fatal("observer reproduced a private account PoW input or child diagnostic")
			}
		}
		for _, guard := range guards {
			guard()
		}
		guardExpected()
		for _, path := range []string{statePath, initialPath} {
			if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
				t.Fatal("read-only PoW observation obtained writer ownership")
			}
		}
		files, err := os.ReadDir(private)
		if err != nil || len(files) != 0 {
			t.Fatal("account PoW observation left raw private files")
		}
		if mode == "coherent-hash" {
			coherentChecked++
		}
		if mode == "" {
			if outer == 0 {
				matched++
			} else {
				blocked++
			}
		}
	}
	rows := loadAccountPoWObservations(t)
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) { check(t, row, "") })
		if row.Profile != originalAccountPoWProfile {
			t.Run(row.Name+"/coherent-hash", func(t *testing.T) { check(t, row, "coherent-hash") })
		}
	}
	positives := 0
	for _, row := range rows {
		if row.Profile != originalAccountPoWProfile {
			continue
		}
		if row.NodeResult != "MATCH" {
			t.Fatal("missing recorded positive original PoW method control")
		}
		positives++
		for _, mode := range []string{"missing-retained-header", "missing-collected-proof", "wrong-selected-target", "wrong-selected-tip"} {
			t.Run(fmt.Sprintf("%s/%s", row.Name, mode), func(t *testing.T) { check(t, row, mode) })
		}
	}
	if positives != 2 || matched != 2 || blocked != 62 || coherentChecked != 62 {
		t.Fatalf("compiled PoW inventory differs: positive methods=%d matched=%d blocked=%d coherent=%d", positives, matched, blocked, coherentChecked)
	}
	summary, err := json.Marshal(map[string]any{
		"schema_version": 1, "cases": 134, "observations": 64,
		"original_matched": matched, "collection_blocked": blocked,
		"coherent_hash_signature_rejected": coherentChecked,
		"missing_commitment_refused":       4, "consumer_selection_mismatched": 4,
		"ordinary_commands": 4, "corpus_sha256": accountPoWCorpusSHA256,
		"node_revision":              "c64ed6279ff1d07335dab0ac36156dec8b5b71e9",
		"runtime_acceptance_changed": false, "account_pow_qualified": false,
		"new_signatures_generated": false, "network_pilot_qualified": false,
		"state_value_acceptance": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("node-account-pow-observer %s", summary)
}
