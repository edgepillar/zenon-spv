package conformance_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type momentumVector struct {
	Name     string                `json:"name"`
	Momentum json.RawMessage       `json:"momentum"`
	Header   chain.Header          `json:"header"`
	Content  []chain.AccountHeader `json:"content"`
}

type momentumCorpus struct {
	FormatVersion int `json:"format_version"`
	Source        struct {
		Commit string `json:"commit"`
	} `json:"source"`
	Vectors    []momentumVector `json:"vectors"`
	Chain      momentumSeries   `json:"chain"`
	Transition momentumSeries   `json:"transition"`
}

type momentumSeries struct {
	Anchor       verify.GenesisTrustRoot `json:"anchor"`
	V2FromHeight uint64                  `json:"v2_from_height"`
	Vectors      []momentumVector        `json:"vectors"`
}

func loadCorpus(t *testing.T) momentumCorpus {
	t.Helper()
	raw, err := os.ReadFile("../testdata/conformance/momentum-v1-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var c momentumCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.FormatVersion != 1 || c.Source.Commit != "3a4131e63881058b6ce2ee81d3a41d0033fafc99" {
		t.Fatal("unexpected corpus format or source pin")
	}
	if len(c.Vectors) != 9 || len(c.Chain.Vectors) != 6 || len(c.Transition.Vectors) != 6 {
		t.Fatal("incomplete momentum corpus")
	}
	return c
}

func fetchVectors(t *testing.T, vectors []momentumVector) ([]fetch.DetailedHeader, error) {
	t.Helper()
	wire := make([]json.RawMessage, len(vectors))
	for i, v := range vectors {
		wire[i] = v.Momentum
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params []uint64        `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if request.Method != "ledger.getMomentumsByHeight" ||
			!slices.Equal(request.Params, []uint64{vectors[0].Header.Height, uint64(len(vectors))}) {
			t.Errorf("unexpected RPC request: %+v", request)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": request.ID, "result": map[string]any{"list": wire},
		}); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	return fetch.NewClient(srv.URL).FetchByHeightDetailed(context.Background(), vectors[0].Header.Height, uint64(len(vectors)))
}

func TestNodeMomentumHashVectors(t *testing.T) {
	c := loadCorpus(t)
	for _, v := range slices.Concat(c.Vectors, c.Chain.Vectors, c.Transition.Vectors) {
		t.Run(v.Name, func(t *testing.T) {
			if got := chain.MomentumContentHash(v.Content); got != v.Header.ContentHash {
				t.Fatalf("content hash = %x, node = %x", got, v.Header.ContentHash)
			}
			if !ed25519.Verify(v.Header.PublicKey, v.Header.HeaderHash[:], v.Header.Signature) {
				t.Fatal("invalid fixture signature")
			}
			if got := v.Header.ComputeHash(); got != v.Header.HeaderHash {
				t.Fatalf("header hash = %x, node = %x", got, v.Header.HeaderHash)
			}
		})
	}
}

func TestNodeMomentumRPCVectors(t *testing.T) {
	for _, v := range loadCorpus(t).Vectors {
		t.Run(v.Name, func(t *testing.T) {
			got, err := fetchVectors(t, []momentumVector{v})

			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got[0].Header, v.Header) || !slices.Equal(got[0].Content, v.Content) {
				t.Fatalf("RPC conversion differs from node values: %+v", got[0])
			}
		})
	}
}

func TestNodeMomentumV2RefusedWithoutPartialProgress(t *testing.T) {
	c := loadCorpus(t)
	policy := verify.Policy{W: 1}
	for _, v := range c.Vectors {
		if v.Header.Version != 2 {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			state := verify.NewHeaderState(verify.GenesisTrustRoot{
				ChainID: v.Header.ChainIdentifier, Height: v.Header.Height - 1, HeaderHash: v.Header.PreviousHash,
			}, policy)
			result, after := verify.VerifyHeaders([]chain.Header{v.Header}, state, policy)
			if result.Outcome != verify.OutcomeRefused || result.Reason != verify.ReasonProtocolProfileRequired ||
				len(result.Proven) != 0 || !reflect.DeepEqual(after, state) {
				t.Fatalf("v2 must refuse without guarantees or state changes: %s", result)
			}

		})
	}
}

func TestNodeMomentumChainAndCommitment(t *testing.T) {
	c := loadCorpus(t)
	detailed, err := fetchVectors(t, c.Chain.Vectors)
	if err != nil {
		t.Fatal(err)
	}
	headers := make([]chain.Header, len(detailed))
	for i, d := range detailed {
		headers[i] = d.Header
		if !reflect.DeepEqual(d.Header, c.Chain.Vectors[i].Header) {
			t.Fatalf("chain header %d differs from node", i)
		}
	}
	policy := verify.Policy{W: 5}
	initial := verify.NewHeaderState(c.Chain.Anchor, policy)
	missingProducer, unchanged := verify.VerifyHeadersWithOptions(headers, initial, verify.VerifyOptions{
		Policy: policy, ProducerAuth: verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired},
	})
	if missingProducer.Outcome != verify.OutcomeRefused || missingProducer.Reason != verify.ReasonProducerSetUnknown ||
		len(missingProducer.Proven) != 0 || !reflect.DeepEqual(initial, unchanged) {
		t.Fatalf("required producer policy silently downgraded: %s", missingProducer)
	}
	result, state := verify.VerifyHeaders(headers, initial, policy)
	if result.Outcome != verify.OutcomeAccept {
		t.Fatal(result)
	}
	for _, want := range []verify.Guarantee{verify.GuaranteeHeaderChainIntegrity, verify.GuaranteeSignatureAuthenticity} {
		if !slices.Contains(result.Proven, want) {
			t.Fatalf("missing guarantee %s", want)
		}
	}
	assertBoundedGuarantees(t, result)
	// The first header has exactly five strict-past headers at this tip.
	member := c.Chain.Vectors[0].Content[0]
	evidence := proof.CommitmentEvidence{
		Height: headers[0].Height, Target: member,
		Flat: &proof.FlatContentEvidence{SortedHeaders: c.Chain.Vectors[0].Content},
	}
	commitment := verify.VerifyCommitment(state, evidence, policy)
	if commitment.Outcome != verify.OutcomeAccept || !slices.Contains(commitment.Proven, verify.GuaranteeContentInclusion) {
		t.Fatal(commitment)
	}
	assertBoundedGuarantees(t, commitment)
	// A matching member one header later lacks the requested strict-past depth.
	evidence.Height++
	if got := verify.VerifyCommitment(state, evidence, policy); got.Outcome != verify.OutcomeRefused || got.Reason != verify.ReasonInsufficientFinality {
		t.Fatalf("shallow commitment: %s", got)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := verify.SaveHeaderState(path, state); err != nil {
		t.Fatal(err)
	}
	resumed, err := verify.LoadOrInit(path, c.Chain.Anchor, policy)
	if err != nil || !reflect.DeepEqual(resumed, state) {
		t.Fatalf("resume changed node-derived state: %v", err)
	}
}

func assertBoundedGuarantees(t *testing.T, result verify.Result) {
	t.Helper()
	for _, absent := range []verify.Guarantee{
		verify.GuaranteeProducerAuthorization, verify.GuaranteeCanonicality,
		verify.GuaranteeStateTransition, verify.GuaranteeStateValueInclusion,
	} {
		if slices.Contains(result.Proven, absent) {
			t.Fatalf("synthetic, unauthenticated-producer chain claims %s", absent)
		}
	}
}

func TestNodeMomentumSignedFieldTampering(t *testing.T) {
	c := loadCorpus(t)
	policy := verify.Policy{W: 5}
	cases := []struct {
		name   string
		mutate func(*chain.Header)
		reason verify.ReasonCode
	}{
		{"chain-id", func(h *chain.Header) { h.ChainIdentifier++ }, verify.ReasonChainIDMismatch},
		{"previous-hash", func(h *chain.Header) { h.PreviousHash[0] ^= 1 }, verify.ReasonBrokenLinkage},
		{"height", func(h *chain.Header) { h.Height++ }, verify.ReasonHeightNonMonotonic},
		{"timestamp", func(h *chain.Header) { h.TimestampUnix++ }, verify.ReasonInvalidHash},
		{"data-hash", func(h *chain.Header) { h.DataHash[0] ^= 1 }, verify.ReasonInvalidHash},
		{"content-hash", func(h *chain.Header) { h.ContentHash[0] ^= 1 }, verify.ReasonInvalidHash},
		{"changes-hash", func(h *chain.Header) { h.ChangesHash[0] ^= 1 }, verify.ReasonInvalidHash},
		{"claimed-hash", func(h *chain.Header) { h.HeaderHash[0] ^= 1 }, verify.ReasonInvalidHash},
		{"signature", func(h *chain.Header) { h.Signature[0] ^= 1 }, verify.ReasonInvalidSignature},
		{"public-key", func(h *chain.Header) { h.PublicKey[0] ^= 1 }, verify.ReasonInvalidSignature},
		{"version", func(h *chain.Header) { h.Version = 3 }, verify.ReasonUnsupportedHeaderVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := make([]chain.Header, len(c.Chain.Vectors))
			for i, v := range c.Chain.Vectors {
				headers[i] = v.Header
				headers[i].Signature = slices.Clone(v.Header.Signature)
				headers[i].PublicKey = slices.Clone(v.Header.PublicKey)
			}
			tc.mutate(&headers[2]) // Test rollback after a valid prefix.
			state := verify.NewHeaderState(c.Chain.Anchor, policy)
			result, after := verify.VerifyHeaders(headers, state, policy)
			outcome := verify.OutcomeReject
			if tc.reason == verify.ReasonUnsupportedHeaderVersion {
				outcome = verify.OutcomeRefused
			}
			if result.Outcome != outcome || result.Reason != tc.reason || len(result.Proven) != 0 || !reflect.DeepEqual(after, state) {
				t.Fatalf("tampered input advanced or reported an unexpected result: %s", result)
			}
		})
	}
}

func TestNodeMomentumRPCDataTampering(t *testing.T) {
	v := loadCorpus(t).Vectors[1]
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(v.Momentum, &wire); err != nil {
		t.Fatal(err)
	}
	wire["data"] = json.RawMessage(`"AA=="`)
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	v.Momentum = raw
	got, err := fetchVectors(t, []momentumVector{v})
	if !errors.Is(err, fetch.ErrHashMismatch) || len(got) != 0 {
		t.Fatalf("tampered wire data: headers=%d, err=%v", len(got), err)
	}
}

func TestNodeMomentumMalformedWireEncoding(t *testing.T) {
	cases := []struct {
		name, field string
		value       json.RawMessage
	}{
		{"data-base64", "data", json.RawMessage(`"!"`)},
		{"key-base64", "publicKey", json.RawMessage(`"!"`)},
		{"signature-base64", "signature", json.RawMessage(`"!"`)},
		{"hash-hex-length", "changesHash", json.RawMessage(`"00"`)},
		{"hash-hex-encoding", "changesHash", json.RawMessage(`"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"`)},
		{"height-fraction", "height", json.RawMessage(`1001.5`)},
		{"height-overflow", "height", json.RawMessage(`18446744073709551616`)},
		{"address-bech32", "content", json.RawMessage(`[{"address":"z1invalid","height":1,"hash":"0000000000000000000000000000000000000000000000000000000000000000"}]`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := loadCorpus(t).Vectors[2]
			var wire map[string]json.RawMessage
			if err := json.Unmarshal(v.Momentum, &wire); err != nil {
				t.Fatal(err)
			}
			wire[tc.field] = tc.value
			raw, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			v.Momentum = raw
			if got, err := fetchVectors(t, []momentumVector{v}); err == nil || len(got) != 0 {
				t.Fatalf("malformed wire encoding returned headers=%d, err=%v", len(got), err)
			}
		})
	}
}
