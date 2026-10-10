package conformance_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestCompiledRetentionDepthWorkflow(t *testing.T) {
	bin := buildQueryCLIs(t, "zenon-spv")["zenon-spv"]
	c, bundle := contractBatchBundle(t)
	dir := t.TempDir()
	anchor := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", c.Chain.Anchor)
	config := []string{"--json", "--genesis-config", anchor, "--window", "low", "--retain-headers", "16"}
	configured := runQueryCLI(t, bin, append([]string{"inspect-config"}, config...)...)
	var configuration struct {
		Context verify.VerificationContext `json:"verification_context"`
	}
	if configured.code != 0 || json.Unmarshal(configured.stdout, &configuration) != nil || configuration.Context.SchemaVersion != 2 || configuration.Context.Policy.RetainHeaders != 16 || configuration.Context.Fingerprint == nil {
		t.Fatal("explicit K was not bound to a versioned context")
	}
	pin := hex.EncodeToString(configuration.Context.Fingerprint[:])
	statePath := filepath.Join(dir, "PRIVATE_STATE.json")
	common := append(slices.Clone(config), "--expect-context", pin, "--state", statePath)
	seed := bundle
	seed.Headers = bundle.Headers[:8]
	seedPath := writeCLIJSON(t, dir, "PRIVATE_SEED.json", seed)
	r := checkProcessReport(t, runQueryCLI(t, bin, append([]string{"verify-headers"}, append(slices.Clone(common), seedPath)...)...), 0, "ACCEPT")
	if r.Persistence != "saved" || r.Context.Version != 2 {
		t.Fatal("explicit K was not saved")
	}
	query := bundle
	query.Headers = nil
	queryPath := writeCLIJSON(t, dir, "PRIVATE_QUERY.json", query)
	args := append(slices.Clone(common), "--retained-only", queryPath)
	r = checkProcessReport(t, runQueryCLI(t, bin, append([]string{"verify-commitment"}, args...)...), 2, "REFUSED")
	for _, row := range r.Results {
		if row.Reason != "ReasonInsufficientFinality" {
			t.Fatal("retention weakened the depth requirement")
		}
	}
	peer := newQueryCLIPeer(t, c, false, bundle.Headers[8])
	watch := append([]string{"watch"}, common...)
	advanced := runQueryCLI(t, bin, append(watch, "--once", "--rpc", peer.url, "--safety-margin", "1")...)
	if advanced.code != 0 || !bytes.Contains(advanced.stdout, []byte(`"event":"advanced"`)) {
		t.Fatal("watch did not resume schema 3 and persist progress")
	}
	check := protectCLIState(t, statePath)
	defer check()
	for _, command := range []string{"verify-commitment", "verify-segment"} {
		r = checkProcessReport(t, runQueryCLI(t, bin, append([]string{command}, args...)...), 0, "ACCEPT")
		if r.Context.Version != 2 || r.Persistence != "read_only" || len(r.Results) != 5 {
			t.Fatal("retained query lost explicit history policy")
		}
		check()
	}
	inspected := runQueryCLI(t, bin, append([]string{"inspect-state"}, common...)...)
	var inspection struct {
		Window verify.RetainedSummary `json:"retained_window"`
	}
	if inspected.code != 0 || json.Unmarshal(inspected.stdout, &inspection) != nil || inspection.Window.Count != 9 || inspection.Window.Capacity != 16 || *inspection.Window.DepthEligible != (verify.RetainedDepthRange{FromHeight: 4001, ThroughHeight: 4003}) {
		t.Fatal("inspection did not expose multiple depth-eligible heights")
	}
	before := peer.calls.Load()
	for _, command := range []string{"inspect-state", "watch", "verify-commitment"} {
		omitted := []string{command, "--json", "--genesis-config", anchor, "--state", statePath}
		switch command {
		case "watch":
			omitted = append(omitted, "--once", "--rpc", peer.url)
		case "verify-commitment":
			omitted = append(omitted, "--retained-only", queryPath)
		}
		result := runQueryCLI(t, bin, omitted...)
		if result.code != 70 {
			t.Fatal("schema 3 silently downgraded retention")
		}
		assertOperatorPrivacy(t, result, dir)
		check()
	}
	if peer.calls.Load() != before {
		t.Fatal("missing retention reached RPC")
	}
	wrong := selectQueryCLIOption(common, "--retain-headers", "17")
	if result := runQueryCLI(t, bin, append([]string{"inspect-state"}, wrong...)...); result.code != 70 || !bytes.Contains(result.stdout, []byte(`"stage":"context_pin"`)) {
		t.Fatal("changed K matched a pinned context")
	}
	for _, result := range []queryCLIResult{configured, advanced, inspected} {
		assertOperatorPrivacy(t, result, dir)
	}
}
