package conformance_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Frontiers, targets and ranges are all unmodified pinned-node envelopes.
// This local server is neither a live node nor independent peer evidence.
type delayedCLIPeer struct {
	url      string
	frontier atomic.Uint64
	calls    atomic.Int64
}

func newDelayedCLIPeer(t *testing.T, c accountSegmentCorpus) *delayedCLIPeer {
	t.Helper()
	p := &delayedCLIPeer{}
	p.frontier.Store(5018)
	accounts := map[string][]json.RawMessage{}
	for _, segment := range c.Segments {
		for _, v := range segment.Vectors {
			accounts[segment.RPCAddress] = append(accounts[segment.RPCAddress], v.RPC)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != "PRIVATE_RPC_USER" || password != "PRIVATE_RPC_PASSWORD" || r.URL.Query().Get("token") != "PRIVATE_RPC_QUERY" {
			t.Error("fixture request lost its configured credentials")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var request struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("malformed fixture request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var result any
		var list []json.RawMessage
		valid := false
		switch request.Method {
		case "ledger.getFrontierMomentum":
			valid = len(request.Params) == 0
			result = c.Chain.Vectors[p.frontier.Load()-5001].Momentum
		case "ledger.getMomentumsByHeight":
			var start, count uint64
			valid = len(request.Params) == 2 && json.Unmarshal(request.Params[0], &start) == nil && json.Unmarshal(request.Params[1], &count) == nil &&
				start >= 5001 && start <= 5019 && count > 0 && count <= 5020-start
			if valid {
				for i := uint64(0); i < count; i++ {
					list = append(list, c.Chain.Vectors[start-5001+i].Momentum)
				}
			}
		case "ledger.getAccountBlocksByHeight":
			var address string
			var start, count uint64
			valid = len(request.Params) == 3 && json.Unmarshal(request.Params[0], &address) == nil &&
				json.Unmarshal(request.Params[1], &start) == nil && json.Unmarshal(request.Params[2], &count) == nil &&
				len(accounts[address]) == 3 && start >= 1 && start <= 3 && count > 0 && count <= 4-start
			if valid {
				list = accounts[address][start-1 : start-1+count]
			}
		}
		if !valid {
			t.Error("unexpected fixture query")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if result == nil {
			result = map[string]any{"list": list}
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	p.url = "http://PRIVATE_RPC_USER:PRIVATE_RPC_PASSWORD@" + strings.TrimPrefix(server.URL, "http://") + "?token=PRIVATE_RPC_QUERY"
	return p
}

func TestCompiledDelayedInclusionWorkflow(t *testing.T) {
	bins := buildQueryCLIs(t, "zenon-spv", "fetch-bundle")
	c, bundle := delayedInclusionBundle(t)
	opts, schedule := delayedOptions(t, c)
	dir := t.TempDir()
	anchor := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", c.Chain.Anchor)
	profile := writeCLIJSON(t, dir, "PRIVATE_PROFILE.json", opts.Policy.ProtocolProfile)
	producers := writeCLIJSON(t, dir, "PRIVATE_SCHEDULE.json", schedule)
	config := []string{"--json", "--genesis-config", anchor, "--protocol-profile", profile,
		"--schedule", producers, "--retain-headers", "16", "--window", "low"}
	configured := runQueryCLI(t, bins["zenon-spv"], append([]string{"inspect-config"}, config...)...)
	var configuration struct {
		Context verify.VerificationContext `json:"verification_context"`
	}
	if configured.code != 0 || json.Unmarshal(configured.stdout, &configuration) != nil ||
		configuration.Context.SchemaVersion != 2 || configuration.Context.Fingerprint == nil {
		t.Fatal("delayed workflow did not bind explicit capacity and trust inputs")
	}
	pin := hex.EncodeToString(configuration.Context.Fingerprint[:])
	state := filepath.Join(dir, "PRIVATE_STATE.json")
	common := append(slices.Clone(config), "--expect-context", pin, "--state", state)
	seed := bundle
	seed.Headers = bundle.Headers[:16]
	seedPath := writeCLIJSON(t, dir, "PRIVATE_SEED.json", seed)
	checkProcessReport(t, runQueryCLI(t, bins["zenon-spv"], append([]string{"verify-headers"}, append(slices.Clone(common), seedPath)...)...), 0, "ACCEPT")
	query := bundle
	query.Headers = nil
	queryPath := writeCLIJSON(t, dir, "PRIVATE_QUERY.json", query)
	r := checkProcessReport(t, runQueryCLI(t, bins["zenon-spv"], append([]string{"verify-segment"}, append(slices.Clone(common), "--retained-only", queryPath)...)...), 2, "REFUSED")
	if len(r.Results) != 6 || r.Results[0].Outcome != "ACCEPT" || r.Results[1].Outcome != "ACCEPT" ||
		r.Results[2].Reason != "ReasonInsufficientFinality" || r.Results[3].Outcome != "ACCEPT" ||
		r.Results[4].Outcome != "ACCEPT" || r.Results[5].Reason != "ReasonInsufficientFinality" {
		t.Fatal("compiled segment query ignored per-target depth")
	}
	peer := newDelayedCLIPeer(t, c)
	for _, frontier := range []uint64{5018, 5019} {
		peer.frontier.Store(frontier)
		result := runQueryCLI(t, bins["zenon-spv"], append([]string{"watch"}, append(slices.Clone(common), "--once", "--rpc", peer.url, "--safety-margin", "1")...)...)
		if result.code != 0 || !bytes.Contains(result.stdout, []byte(`"event":"advanced"`)) {
			t.Fatal("watch failed to resume the delayed v2 window")
		}
		assertOperatorPrivacy(t, result, dir)
	}
	unchanged := protectCLIState(t, state)
	t.Cleanup(unchanged)
	candidatePath := filepath.Join(dir, "PRIVATE_COLLECTED.json")
	targets := c.Segments[0].RPCAddress + ":1-3," + c.Segments[1].RPCAddress + ":1-3"
	collected := runQueryCLI(t, bins["fetch-bundle"], "--proof-only", "--segments", targets,
		"--peers", peer.url, "--quorum", "1", "--height", "5018", "--count", "16", "--out", candidatePath)
	if collected.code != 0 {
		t.Fatal("collector failed across separate confirming momentums")
	}
	assertOperatorPrivacy(t, collected, dir)
	candidate, err := proof.LoadHeaderBundle(candidatePath)
	if err != nil || len(candidate.Headers) != 0 || len(candidate.Commitments) != 6 || len(candidate.Segments) != 2 {
		t.Fatal("collector lost delayed node evidence", err)
	}
	expected := map[chain.AccountHeader]bool{}
	for _, evidence := range bundle.Commitments {
		expected[evidence.Target] = true
	}
	before := peer.calls.Load()
	for _, command := range []string{"verify-commitment", "verify-segment"} {
		r = checkProcessReport(t, runQueryCLI(t, bins["zenon-spv"], append([]string{command}, append(slices.Clone(common), "--retained-only", candidatePath)...)...), 0, "ACCEPT")
		if r.Persistence != "read_only" || r.Mode != "retained_only" || r.Tip.Height != 5018 || r.Context == nil ||
			r.Context.Version != 2 || r.Context.Fingerprint == nil || *r.Context.Fingerprint != *configuration.Context.Fingerprint || len(r.Results) != 6 {
			t.Fatal("compiled delayed report lost its context, window or targets")
		}
		seen := map[chain.AccountHeader]bool{}
		for _, row := range r.Results {
			if row.Reference.Account == nil || !expected[*row.Reference.Account] || seen[*row.Reference.Account] || row.Outcome != "ACCEPT" ||
				!slices.Contains(row.Proven, verify.GuaranteeContentInclusion) || !slices.Contains(row.Trust, verify.TrustPersistedState) {
				t.Fatal("compiled report accepted another or repeated account identity")
			}
			seen[*row.Reference.Account] = true
		}
		unchanged()
	}
	inspected := runQueryCLI(t, bins["zenon-spv"], append([]string{"inspect-state"}, common...)...)
	var inspection struct {
		Window verify.RetainedSummary `json:"retained_window"`
	}
	if inspected.code != 0 || json.Unmarshal(inspected.stdout, &inspection) != nil || inspection.Window.Count != 16 ||
		inspection.Window.Oldest == nil || inspection.Window.Oldest.Height != 5003 || inspection.Window.DepthEligible == nil ||
		*inspection.Window.DepthEligible != (verify.RetainedDepthRange{FromHeight: 5003, ThroughHeight: 5012}) {
		t.Fatal("inspection did not preserve the delayed-query range")
	}
	assertOperatorPrivacy(t, inspected, dir)
	if peer.calls.Load() != before {
		t.Fatal("offline delayed query contacted RPC")
	}
}
