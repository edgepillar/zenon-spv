// SPDX-License-Identifier: MIT

package verify_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type experimentalV3Transport func(*http.Request) (*http.Response, error)

func (f experimentalV3Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestExperimentalV3RecordedRPCToOwnedRootAndResume(t *testing.T) {
	raw, err := os.ReadFile("../testdata/conformance/candidate-v3-node-rpc.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if len(raw) != 15475 || hex.EncodeToString(sum[:]) != "4ac2da237eead98f146d931a27679a7251a5a9ef5e109920b9f7fd1f3a383e57" {
		t.Fatal("recorded RPC bytes changed")
	}
	var recorded struct {
		Rows []struct {
			Signed   bool   `json:"existing_signature_valid"`
			Wire     string `json:"wire_json"`
			Producer string `json:"producer_raw_hex"`
		} `json:"rows"`
	}
	if json.Unmarshal(raw, &recorded) != nil || len(recorded.Rows) != 8 {
		t.Fatal("RPC fixture shape")
	}
	wires := []json.RawMessage{}
	for _, row := range recorded.Rows {
		if row.Signed {
			wires = append(wires, json.RawMessage(row.Wire))
		}
	}
	if len(wires) != 3 {
		t.Fatal("expected three original public signatures")
	}
	client := fetch.NewClient("https://candidate.invalid")
	client.HTTP.Transport = experimentalV3Transport(func(req *http.Request) (*http.Response, error) {
		var call struct {
			Method string    `json:"method"`
			Params [2]uint64 `json:"params"`
		}
		if json.NewDecoder(req.Body).Decode(&call) != nil || call.Method != "ledger.getMomentumsByHeight" || call.Params != [2]uint64{12, 3} {
			t.Fatal("selected consumer range changed")
		}
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"list": wires, "count": 3}})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})
	candidates, err := client.FetchCandidateV3ByHeight(context.Background(), 12, 3)
	if err != nil || len(candidates) != 3 {
		t.Fatal("recorded RPC range failed", err)
	}
	var genesis, anchor chain.Hash
	if genesis.UnmarshalText([]byte("0385d849ee33b94c8783288c148e3ae741c2ecec98b08b3f59d6bcc219168fe5")) != nil || anchor.UnmarshalText([]byte("2b584eb276428450a3485d18df309d37352110d59cd670b25bc774837b5f5768")) != nil {
		t.Fatal("fixture trust inputs")
	}
	profile := verify.ExperimentalV3Profile{Version: 1, Genesis: verify.GenesisTrustRoot{ChainID: 100, Height: 1, HeaderHash: genesis}, Anchor: verify.GenesisTrustRoot{ChainID: 100, Height: 11, HeaderHash: anchor}, FirstV3Height: 12, ValidThrough: 14, NodeRevision: verify.ExperimentalV3NodeRevision, Source: "isolated original-node fixture; not authenticated network activation"}
	policy := verify.ExperimentalV3Policy{W: 1, RetainHeaders: 2, MaxBatchHeaders: 3}
	entries := make([]verify.ProducerEntry, 3)
	headers := make([]chain.CandidateV3Header, 3)
	for i, c := range candidates {
		// This schedule is an explicit test configuration from a pinned public
		// fixture. It is not an independently selected live producer schedule.
		producer, err := hex.DecodeString(recorded.Rows[i].Producer)
		if err != nil || len(producer) != 20 {
			t.Fatal("fixture producer")
		}
		var address chain.Address
		copy(address[:], producer)
		entries[i] = verify.ProducerEntry{Height: uint64(12 + i), TimestampUnix: uint64(1000000110 + 10*i), ProducingAddr: address}
		headers[i] = c.Header
	}
	schedule, err := verify.NewProducerSchedule(100, []verify.ProducerCoverage{{FromHeight: 12, ThroughHeight: 14}}, entries, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := verify.ExperimentalV3ContextFor(profile, policy, schedule)
	if err != nil {
		t.Fatal(err)
	}
	state, err := verify.NewExperimentalV3State(profile, policy, schedule, ctx.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	result, state := state.Extend(headers)
	if result.Outcome != verify.OutcomeAccept {
		t.Fatal(result)
	}
	root, err := state.RootAt(13, headers[1].Header.HeaderHash, ctx.Fingerprint)
	if err != nil || root != headers[1].StateRoot {
		t.Fatal("owned header root lost", err)
	}
	path := filepath.Join(t.TempDir(), "owned-v3.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	resumed, err := verify.LoadTrustedExperimentalV3State(path, profile, policy, schedule, ctx.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if actual, err := resumed.RootAt(13, headers[1].Header.HeaderHash, ctx.Fingerprint); err != nil || actual != root {
		t.Fatal("resumed consumer root mismatch", err)
	}
	native, err := verify.NewVerifiedState(profile.Anchor, verify.VerifyOptions{Policy: verify.Policy{W: 1, RetainHeaders: 2, MaxHeaders: 3}})
	if err != nil {
		t.Fatal(err)
	}
	refused, _ := native.Extend([]chain.Header{headers[0].Header})
	if refused.Outcome != verify.OutcomeRefused || refused.Reason != verify.ReasonUnsupportedHeaderVersion {
		t.Fatal("experimental workflow enabled production v3", refused)
	}
	for _, guarantee := range result.Proven {
		if guarantee == verify.GuaranteeStateValueInclusion || guarantee == verify.GuaranteeCanonicality || guarantee == verify.GuaranteeStateTransition {
			t.Fatal("recorded workflow emitted an unsupported guarantee")
		}
	}
}
