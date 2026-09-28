package conformance_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/syncer"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// TestOfflineWatchPeerFaults exercises the real RPC, quorum, verification,
// persistence, and trusted-resume paths against local peers. It is deliberately
// synthetic: agreed RPC responses are not evidence of consensus finality.
func TestOfflineWatchPeerFaults(t *testing.T) {
	for _, tc := range []struct {
		name       string
		peers      [3]string
		want       string
		detail     string
		advance    bool
		caughtUp   bool
		expire     bool
		maxHeaders int
	}{
		{name: "healthy", advance: true, want: "ACCEPT"},
		{name: "one-unavailable", peers: [3]string{"", "", "unavailable"}, advance: true, want: "ACCEPT"},
		{name: "one-stale", peers: [3]string{"", "", "stale"}, advance: true, want: "ACCEPT"},
		{name: "quorum-loss", peers: [3]string{"", "unavailable", "unavailable"}, want: "REFUSED ReasonMissingEvidence", detail: "not enough peers"},
		{name: "valid-peer-fork", peers: [3]string{"", "", "fork"}, want: "REFUSED ReasonMissingEvidence", detail: "peers disagree"},
		{name: "invalid-signature", peers: [3]string{"signature", "signature", "signature"}, want: "REJECT ReasonInvalidSignature"},
		{name: "broken-anchor-link", peers: [3]string{"link", "link", "link"}, want: "REJECT ReasonBrokenLinkage"},
		{name: "unauthorized-producer", peers: [3]string{"producer", "producer", "producer"}, want: "REJECT ReasonUnauthorizedProducer"},
		{name: "missing-v2-price", peers: [3]string{"price", "price", "price"}, want: "REFUSED ReasonMissingEvidence"},
		{name: "expired-profile", expire: true, want: "REFUSED ReasonProtocolProfileCoverage"},
		{name: "oversized-header-batch", maxHeaders: 2, want: "REFUSED ReasonOversizedHeaders"},
		{name: "all-stale", peers: [3]string{"stale", "stale", "stale"}, caughtUp: true, want: "ACCEPT (caught up"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, headers, policy := transitionFixture(t)
			policy.W, policy.MaxHeaders = 1, tc.maxHeaders
			if tc.expire {
				policy.ProtocolProfile.ValidThrough = 2004
			}
			entries := make([]verify.ProducerEntry, len(headers))
			for i, h := range headers {
				entries[i] = verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix,
					ProducingAddr: chain.PubKeyToAddress(h.PublicKey)}
			}
			schedule, err := verify.NewProducerSchedule(c.Transition.Anchor.ChainID,
				[]verify.ProducerCoverage{{FromHeight: 2001, ThroughHeight: 2006}}, entries, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			authorizer := verify.NewScheduleAuthorizer(schedule)
			opts := verify.VerifyOptions{Policy: policy, ProducerAuth: verify.ProducerAuthOptions{
				Mode: verify.ProducerAuthRequired, Authorizer: authorizer}}
			initial, err := verify.NewVerifiedState(c.Transition.Anchor, opts)
			if err != nil {
				t.Fatal(err)
			}
			result, initial := initial.Extend(headers[:2])
			if result.Outcome != verify.OutcomeAccept {
				t.Fatal(result)
			}
			path := filepath.Join(t.TempDir(), "state.json")
			if err := initial.Save(path); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			urls := make([]string, len(tc.peers))
			for i, mode := range tc.peers {
				urls[i] = startFaultPeer(t, c.Transition.Vectors, mode, i)
			}
			multi := fetch.NewMultiClient(urls)
			multi.Quorum = 2
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			out := &oneTickLog{cancel: cancel}
			saves := 0
			loop := syncer.Loop{Multi: multi, StatePath: path, Genesis: c.Transition.Anchor,
				Policy: policy, Authorizer: authorizer, SafetyMargin: 1, BatchSize: 3,
				Interval: time.Hour, Out: out,
				SaveState: func(path string, snapshot verify.HeaderState) error {
					saves++
					return verify.SaveHeaderState(path, snapshot)
				}}
			if err := loop.Run(ctx); err != nil || !out.ticked {
				t.Fatalf("watch did not complete a bounded tick: %v; %s", err, out.String())
			}
			log := out.String()
			if !strings.Contains(log, "tick: "+tc.want) || !strings.Contains(log, tc.detail) {
				t.Fatalf("unexpected outcome, want %q / %q: %s", tc.want, tc.detail, log)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.advance && !bytes.Equal(before, after) {
				t.Fatal("non-progress tick replaced the trusted state with different bytes")
			}
			wantSaves := 0
			if tc.advance || tc.caughtUp {
				wantSaves = 1
			} else if strings.Contains(log, "tick: ACCEPT") {
				t.Fatal("failed evidence reported ACCEPT")
			}
			if saves != wantSaves {
				t.Fatalf("save calls=%d, want %d", saves, wantSaves)
			}
			resumed, err := verify.LoadTrustedState(path, c.Transition.Anchor, opts)
			if err != nil {
				t.Fatal(err)
			}
			wantTip := headers[1]
			if tc.advance {
				wantTip = headers[4]
				v := c.Transition.Vectors[3]
				r := resumed.VerifyCommitment(proof.CommitmentEvidence{Height: v.Header.Height,
					Target: v.Content[0], Flat: &proof.FlatContentEvidence{SortedHeaders: v.Content}})
				if r.Outcome != verify.OutcomeAccept || slices.Contains(r.Proven, verify.GuaranteeCanonicality) {
					t.Fatalf("resumed commitment violated its bounded guarantees: %s", r)
				}
				for _, tag := range []verify.TrustAssumption{verify.TrustConfiguredAnchor, verify.TrustPersistedState,
					verify.TrustExternalProtocolProfile, verify.TrustExternalProducerSchedule} {
					if !slices.Contains(r.TrustAssumptions, tag) {
						t.Errorf("resumed proof omitted %s", tag)
					}
				}
			}
			if tip, _ := resumed.Tip(); tip.HeaderHash != wantTip.HeaderHash {
				t.Fatalf("persisted tip differs from expected height %d", wantTip.Height)
			}
		})
	}
}

type oneTickLog struct {
	bytes.Buffer
	cancel context.CancelFunc
	ticked bool
}

func (w *oneTickLog) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if strings.Contains(string(p), "tick: ") {
		w.ticked = true
		w.cancel()
	}
	return n, err
}

func startFaultPeer(t *testing.T, vectors []momentumVector, mode string, peer int) string {
	t.Helper()
	wire := faultPeerWire(t, vectors, mode, peer)
	if mode == "stale" {
		wire = wire[:2]
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "unavailable" {
			http.Error(w, "synthetic peer unavailable", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params []uint64        `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var response any
		switch req.Method {
		case "ledger.getFrontierMomentum":
			response = wire[len(wire)-1]
		case "ledger.getMomentumsByHeight":
			if len(req.Params) != 2 || req.Params[0] < 2001 || req.Params[0]-2001 >= uint64(len(wire)) ||
				req.Params[1] == 0 || req.Params[1] > uint64(len(wire))-(req.Params[0]-2001) {
				http.Error(w, "requested height is unavailable", http.StatusNotFound)
				return
			}
			start := req.Params[0] - 2001
			response = map[string]any{"list": wire[start : start+req.Params[1]]}
		default:
			t.Errorf("unexpected method: %s", req.Method)
			http.Error(w, "unsupported method", http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": response}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func faultPeerWire(t *testing.T, vectors []momentumVector, mode string, peer int) []json.RawMessage {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 99 // Deterministic signing material for synthetic momentum fixtures.
	key := ed25519.NewKeyFromSeed(seed)
	wire := make([]json.RawMessage, len(vectors))
	var previous chain.Hash
	for i, v := range vectors {
		h := v.Header
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(v.Momentum, &fields); err != nil {
			t.Fatal(err)
		}
		if i >= 2 {
			switch mode {
			case "signature":
				if i == 2 {
					h.Signature = slices.Clone(h.Signature)
					h.Signature[0] ^= 1
				}
			case "fork", "link", "producer":
				if mode != "producer" {
					h.PreviousHash = previous
					if mode == "link" && i == 2 {
						h.PreviousHash = chain.Hash{0xff}
					}
					if mode == "fork" {
						h.TimestampUnix += uint64(peer+1) * 10
					}
					h.HeaderHash = h.ComputeHash()
				}
				h.PublicKey = key.Public().(ed25519.PublicKey)
				h.Signature = ed25519.Sign(key, h.HeaderHash[:])
			}
		}
		for name, value := range map[string]any{"hash": h.HeaderHash, "previousHash": h.PreviousHash,
			"timestamp": h.TimestampUnix, "publicKey": h.PublicKey, "signature": h.Signature} {
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			fields[name] = encoded
		}
		if mode == "price" && i >= 2 {
			delete(fields, "nextFusionPrice")
		}
		encoded, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		wire[i], previous = encoded, h.HeaderHash
	}
	return wire
}
